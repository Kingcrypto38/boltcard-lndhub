import { User, Lock, Paym, Invo } from '../class/';
import Frisbee from 'frisbee';
const config = require('../config');
let express = require('express');
let router = express.Router();
let logger = require('../utils/logger');
var rp = require('request-promise');
const MIN_BTC_BLOCK = 670000;
if (process.env.NODE_ENV !== 'prod') {
  console.log('using config', JSON.stringify(config));
}

var Redis = require('ioredis');
var redis = new Redis(config.redis);
redis.monitor(function (err, monitor) {
  monitor.on('monitor', function (time, args, source, database) {
    // console.log('REDIS', JSON.stringify(args));
  });
});

/****** START SET FEES FROM CONFIG AT STARTUP ******/
/** GLOBALS */
global.forwardFee = config.forwardReserveFee || 0.01;
global.internalFee = config.intraHubFee || 0.003;
/****** END SET FEES FROM CONFIG AT STARTUP ******/

let bitcoinclient = require('../bitcoin');
let lightning = require('../lightning');
let identity_pubkey = false;
// ###################### SMOKE TESTS ########################

if (config.bitcoind) {
  bitcoinclient.request('getblockchaininfo', false, function (err, info) {
    if (info && info.result && info.result.blocks) {
      if (info.result.chain === 'mainnet' && info.result.blocks < MIN_BTC_BLOCK && !config.forceStart) {
        console.error('bitcoind is not caught up');
        process.exit(1);
      }
      console.log('bitcoind getblockchaininfo:', info);
    } else {
      console.error('bitcoind failure:', err, info);
      process.exit(2);
    }
  });
}

lightning.getInfo({}, function (err, info) {
  if (err) {
    console.error('lnd failure');
    console.dir(err);
    process.exit(3);
  }
  if (info) {
    console.info('lnd getinfo:', info);
    if (!info.synced_to_chain && !config.forceStart) {
      console.error('lnd not synced');
      // process.exit(4);
    }
    identity_pubkey = info.identity_pubkey;
  }
});

redis.info(function (err, info) {
  if (err || !info) {
    console.error('redis failure');
    process.exit(5);
  }
});

const subscribeInvoicesCallCallback = async function (response) {
  if (response.state === 'SETTLED') {
    const LightningInvoiceSettledNotification = {
      memo: response.memo,
      preimage: response.r_preimage.toString('hex'),
      hash: response.r_hash.toString('hex'),
      amt_paid_sat: response.amt_paid_msat ? Math.floor(response.amt_paid_msat / 1000) : response.amt_paid_sat,
    };
    // obtaining a lock, to make sure we push to groundcontrol only once
    // since this web server can have several instances running, and each will get the same callback from LND
    // and dont release the lock - it will autoexpire in a while
    let lock = new Lock(redis, 'groundcontrol_hash_' + LightningInvoiceSettledNotification.hash);
    if (!(await lock.obtainLock())) {
      return;
    }
    let invoice = new Invo(redis, bitcoinclient, lightning);
    await invoice._setIsPaymentHashPaidInDatabase(
      LightningInvoiceSettledNotification.hash,
      LightningInvoiceSettledNotification.amt_paid_sat || 1,
    );
    const user = new User(redis, bitcoinclient, lightning);
    user._userid = await user.getUseridByPaymentHash(LightningInvoiceSettledNotification.hash);
    await user.clearBalanceCache();
    console.log('payment', LightningInvoiceSettledNotification.hash, 'was paid, posting to GroundControl...');
    const baseURI = process.env.GROUNDCONTROL;
    if (!baseURI) return;
    const _api = new Frisbee({ baseURI: baseURI });
    const apiResponse = await _api.post(
      '/lightningInvoiceGotSettled',
      Object.assign(
        {},
        {
          headers: {
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
          },
          body: LightningInvoiceSettledNotification,
        },
      ),
    );
    console.log('GroundControl:', apiResponse.originalResponse.status);
  }
};
let subscribeInvoicesCall = lightning.subscribeInvoices({});
subscribeInvoicesCall.on('data', subscribeInvoicesCallCallback);
subscribeInvoicesCall.on('status', function (status) {
  // The current status of the stream.
});
subscribeInvoicesCall.on('end', function () {
  // The server has closed the stream.
});

let lightningDescribeGraph = {};
function updateDescribeGraph() {
  console.log('updateDescribeGraph()');
  lightning.describeGraph({ include_unannounced: true }, function (err, response) {
    if (!err) lightningDescribeGraph = response;
    console.log('updated graph');
  });
}
if (config.enableUpdateDescribeGraph) {
  updateDescribeGraph();
  setInterval(updateDescribeGraph, 120000);
}

// ######################## ROUTES ########################

const rateLimit = require('express-rate-limit');
const postLimiter = rateLimit({
  windowMs: 30 * 60 * 1000,
  max: config.postRateLimit || 100,
});

router.post('/create', postLimiter, async function (req, res) {
  logger.log('/create', [req.id]);
  // Valid if the partnerid isn't there or is a string (same with accounttype)
  if (! (
        (!req.body.partnerid || (typeof req.body.partnerid === 'string' || req.body.partnerid instanceof String))
        && (!req.body.accounttype || (typeof req.body.accounttype === 'string' || req.body.accounttype instanceof String))
      ) ) return errorBadArguments(res);
  
  if (config.sunset) return errorSunset(res);

  let u = new User(redis, bitcoinclient, lightning);
  await u.create();
  await u.saveMetadata({ partnerid: req.body.partnerid, accounttype: req.body.accounttype, created_at: new Date().toISOString() });
  res.send({ login: u.getLogin(), password: u.getPassword() });
});

router.post('/auth', postLimiter, async function (req, res) {
  logger.log('/auth', [req.id]);
  if (!((req.body.login && req.body.password) || req.body.refresh_token)) return errorBadArguments(res);

  let u = new User(redis, bitcoinclient, lightning);

  if (req.body.refresh_token) {
    // need to refresh token
    if (await u.loadByRefreshToken(req.body.refresh_token)) {
      res.send({ refresh_token: u.getRefreshToken(), access_token: u.getAccessToken() });
    } else {
      return errorBadAuth(res);
    }
  } else {
    // need to authorize user
    let result = await u.loadByLoginAndPassword(req.body.login, req.body.password);
    if (result) res.send({ refresh_token: u.getRefreshToken(), access_token: u.getAccessToken() });
    else errorBadAuth(res);
  }
});

router.post('/addinvoice', postLimiter, async function (req, res) {
  logger.log('/addinvoice', [req.id]);
  let u = new User(redis, bitcoinclient, lightning);
  if (!(await u.loadByAuthorization(req.headers.authorization))) {
    return errorBadAuth(res);
  }
  logger.log('/addinvoice', [req.id, 'userid: ' + u.getUserId()]);

  if (!req.body.amt || /*stupid NaN*/ !(req.body.amt > 0)) return errorBadArguments(res);

  if (config.sunset) return errorSunsetAddInvoice(res);

  const invoice = new Invo(redis, bitcoinclient, lightning);
  const r_preimage = invoice.makePreimageHex();
  lightning.addInvoice(
    { memo: req.body.memo, value: req.body.amt, expiry: 3600 * 24, r_preimage: Buffer.from(r_preimage, 'hex').toString('base64') },
    async function (err, info) {
      if (err) return errorLnd(res);

      info.pay_req = info.payment_request; // client backwards compatibility
      await u.saveUserInvoice(info);
      await invoice.savePreimage(r_preimage);

      res.send(info);
    },
  );
});

router.post('/payinvoice', postLimiter, async function (req, res) {
  let u = new User(redis, bitcoinclient, lightning);
  if (!(await u.loadByAuthorization(req.headers.authorization))) {
    return errorBadAuth(res);
  }

  logger.log('/payinvoice', [req.id, 'userid: ' + u.getUserId(), 'invoice: ' + req.body.invoice]);

  if (!req.body.invoice) return errorBadArguments(res);
  let freeAmount = false;
  if (req.body.amount) {
    freeAmount = parseInt(req.body.amount);
    if (freeAmount <= 0) return errorBadArguments(res);
  }

  // obtaining a lock
  let lock = new Lock(redis, 'invoice_paying_for_' + u.getUserId());
  if (!(await lock.obtainLock())) {
    return errorGeneralServerError(res);
  }

  let userBalance;
  try {
    userBalance = await u.getCalculatedBalance();
  } catch (Error) {
    logger.log('', [req.id, 'error running getCalculatedBalance():', Error.message]);
    lock.releaseLock();
    return errorTryAgainLater(res);
  }

  lightning.decodePayReq({ pay_req: req.body.invoice }, async function (err, info) {
    if (err) {
      await lock.releaseLock();
      return errorNotAValidInvoice(res);
    }

    if (+info.num_satoshis === 0) {
      // 'tip' invoices
      info.num_satoshis = freeAmount;
    }

    logger.log('/payinvoice', [req.id, 'userBalance: ' + userBalance, 'num_satoshis: ' + info.num_satoshis]);

    if (userBalance >= +info.num_satoshis + Math.floor(info.num_satoshis * forwardFee) + 1) {
      // got enough balance, including 1% of payment amount - reserve for fees

      if (identity_pubkey === info.destination) {
        // this is internal invoice
        // now, receiver add balance
        let userid_payee = await u.getUseridByPaymentHash(info.payment_hash);
        if (!userid_payee) {
          await lock.releaseLock();
          return errorGeneralServerError(res);
        }

        if (await u.getPaymentHashPaid(info.payment_hash)) {
          // this internal invoice was paid, no sense paying it again
          await lock.releaseLock();
          return errorLnd(res);
        }

        let UserPayee = new User(redis, bitcoinclient, lightning);
        UserPayee._userid = userid_payee; // hacky, fixme
        await UserPayee.clearBalanceCache();

        // sender spent his balance:
        await u.clearBalanceCache();
        await u.savePaidLndInvoice({
          timestamp: parseInt(+new Date() / 1000),
          type: 'paid_invoice',
          value: +info.num_satoshis + Math.floor(info.num_satoshis * internalFee),
          fee: Math.floor(info.num_satoshis * internalFee),
          memo: decodeURIComponent(info.description),
          pay_req: req.body.invoice,
        });

        const invoice = new Invo(redis, bitcoinclient, lightning);
        invoice.setInvoice(req.body.invoice);
        await invoice.markAsPaidInDatabase();

        // now, faking LND callback about invoice paid:
        const preimage = await invoice.getPreimage();
        if (preimage) {
          subscribeInvoicesCallCallback({
            state: 'SETTLED',
            memo: info.description,
            r_preimage: Buffer.from(preimage, 'hex'),
            r_hash: Buffer.from(info.payment_hash, 'hex'),
            amt_paid_sat: +info.num_satoshis,
          });
        }
        await lock.releaseLock();
        return res.send(info);
      }

      // else - regular lightning network payment:

      var call = lightning.sendPayment();
      call.on('data', async function (payment) {
        // payment callback
        await u.unlockFunds(req.body.invoice);
        if (payment && payment.payment_route && payment.payment_route.total_amt_msat) {
          let PaymentShallow = new Paym(false, false, false);
          payment = PaymentShallow.processSendPaymentResponse(payment);
          payment.pay_req = req.body.invoice;
          payment.decoded = info;
          await u.savePaidLndInvoice(payment);
          await u.clearBalanceCache();
          lock.releaseLock();

          logger.log('/payinvoice sendPayment callback', payment);
          if(req.body.loginid) {
            //send notification through ground control
            const LightningInvoiceSettledNotification = {
              payment_request: req.body.invoice,
              amt_paid_sat: +info.num_satoshis + Math.floor(info.num_satoshis * forwardFee), // amt is used only for 'tip' invoices
              userid: req.body.loginid,
              memo: info.description
            };
            logger.log('/payinvoice', 'payment made by ', req.body.loginid, ', posting to GroundControl...');
            console.log('payment made by ', req.body.loginid, ', posting to GroundControl...');
            console.log(LightningInvoiceSettledNotification, ', posting to GroundControl...');

            const baseURI = process.env.GROUNDCONTROL;
            if (baseURI) {
              const _api = new Frisbee({ baseURI: baseURI });
              const apiResponse = await _api.post(
                '/userPaidLightningInvoice',
                Object.assign(
                  {},
                  {
                    headers: {
                      'Access-Control-Allow-Origin': '*',
                      'Content-Type': 'application/json',
                    },
                    body: LightningInvoiceSettledNotification,
                  },
                ),
              );
              console.log('GroundControl:', apiResponse.originalResponse.status);
            }
            
          }

          res.send(payment);


        } else {
          // payment failed
          lock.releaseLock();
          return errorPaymentFailed(res);
        }
      });
      if (!info.num_satoshis) {
        // tip invoice, but someone forgot to specify amount
        await lock.releaseLock();
        return errorBadArguments(res);
      }
      let inv = {
        payment_request: req.body.invoice,
        amt: info.num_satoshis, // amt is used only for 'tip' invoices
        fee_limit: { fixed: Math.floor(info.num_satoshis * forwardFee) + 1 },
      };
      try {
        await u.lockFunds(req.body.invoice, info);
        call.write(inv);

      } catch (Err) {
        await lock.releaseLock();
        return errorPaymentFailed(res);
      }
    } else {
      await lock.releaseLock();
      return errorNotEnougBalance(res);
    }
  });
});

router.get('/getbtc', async function (req, res) {
  logger.log('/getbtc', [req.id]);
  let u = new User(redis, bitcoinclient, lightning);
  await u.loadByAuthorization(req.headers.authorization);

  if (!u.getUserId()) {
    return errorBadAuth(res);
  }

  if (config.sunset) return errorSunsetAddInvoice(res);

  let address = await u.getAddress();
  if (!address) {
    await u.generateAddress();
    address = await u.getAddress();
  }
  u.watchAddress(address);

  res.send([{ address }]);
});

router.get('/checkpayment/:payment_hash', async function (req, res) {
  logger.log('/checkpayment', [req.id]);
  let u = new User(redis, bitcoinclient, lightning);
  await u.loadByAuthorization(req.headers.authorization);

  if (!u.getUserId()) {
    return errorBadAuth(res);
  }

  let paid = true;
  if (!(await u.getPaymentHashPaid(req.params.payment_hash))) {
    // Not found on cache
    paid = await u.syncInvoicePaid(req.params.payment_hash);
  }
  res.send({ paid: paid });
});

router.get('/balance', postLimiter, async function (req, res) {
  let u = new User(redis, bitcoinclient, lightning);
  try {
    logger.log('/balance', [req.id]);
    if (!(await u.loadByAuthorization(req.headers.authorization))) {
      return errorBadAuth(res);
    }
    logger.log('/balance', [req.id, 'userid: ' + u.getUserId()]);

    if (!(await u.getAddress())) await u.generateAddress(); // onchain address needed further
    await u.accountForPosibleTxids();
    let balance = await u.getBalance();
    if (balance < 0) balance = 0;
    res.send({ BTC: { AvailableBalance: balance } });
  } catch (Error) {
    logger.log('', [req.id, 'error getting balance:', Error.message, 'userid:', u.getUserId()]);
    return errorGeneralServerError(res);
  }
});

router.get('/getinfo', postLimiter, async function (req, res) {
  logger.log('/getinfo', [req.id]);
  let u = new User(redis, bitcoinclient, lightning);
  if (!(await u.loadByAuthorization(req.headers.authorization))) {
    return errorBadAuth(res);
  }

  lightning.getInfo({}, function (err, info) {
    if (err) return errorLnd(res);
    res.send(info);
  });
});

router.get('/getinfobolt', postLimiter, async function (req, res) {
  logger.log('/getinfobolt', [req.id]);
  let u = new User(redis, bitcoinclient, lightning);
  if (!(await u.loadByAuthorization(req.headers.authorization))) {
    return errorBadAuth(res);
  }

  lightning.getInfo({}, function (err, info) {
    if (err) return errorLnd(res);
    res.send(info);
  });
});

router.get('/gettxs', postLimiter, async function (req, res) {
  logger.log('/gettxs', [req.id]);
  let u = new User(redis, bitcoinclient, lightning);
  if (!(await u.loadByAuthorization(req.headers.authorization))) {
    return errorBadAuth(res);
  }
  logger.log('/gettxs', [req.id, 'userid: ' + u.getUserId()]);

  if (!(await u.getAddress())) await u.generateAddress(); // onchain addr needed further
  try {
    await u.accountForPosibleTxids();
    let txs = await u.getTxs();
    let lockedPayments = await u.getLockedPayments();
    for (let locked of lockedPayments) {
      txs.push({
        type: 'paid_invoice',
        fee: Math.floor(locked.amount * forwardFee) /* feelimit */,
        value: locked.amount + Math.floor(locked.amount * forwardFee) /* feelimit */,
        timestamp: locked.timestamp,
        memo: 'Payment in transition',
      });
    }
    res.send(txs);
  } catch (Err) {
    logger.log('', [req.id, 'error gettxs:', Err.message, 'userid:', u.getUserId()]);
    res.send([]);
  }
});

router.get('/getuserinvoices', postLimiter, async function (req, res) {
  logger.log('/getuserinvoices', [req.id]);
  let u = new User(redis, bitcoinclient, lightning);
  if (!(await u.loadByAuthorization(req.headers.authorization))) {
    return errorBadAuth(res);
  }
  logger.log('/getuserinvoices', [req.id, 'userid: ' + u.getUserId()]);

  try {
    let invoices = await u.getUserInvoices(req.query.limit);
    res.send(invoices);
  } catch (Err) {
    logger.log('', [req.id, 'error getting user invoices:', Err.message, 'userid:', u.getUserId()]);
    res.send([]);
  }
});

router.get('/getpending', postLimiter, async function (req, res) {
  logger.log('/getpending', [req.id]);
  let u = new User(redis, bitcoinclient, lightning);
  if (!(await u.loadByAuthorization(req.headers.authorization))) {
    return errorBadAuth(res);
  }
  logger.log('/getpending', [req.id, 'userid: ' + u.getUserId()]);

  if (!(await u.getAddress())) await u.generateAddress(); // onchain address needed further
  await u.accountForPosibleTxids();
  let txs = await u.getPendingTxs();
  res.send(txs);
});

router.get('/decodeinvoice', postLimiter, async function (req, res) {
  logger.log('/decodeinvoice', [req.id]);
  let u = new User(redis, bitcoinclient, lightning);
  if (!(await u.loadByAuthorization(req.headers.authorization))) {
    return errorBadAuth(res);
  }

  if (!req.query.invoice) return errorGeneralServerError(res);

  lightning.decodePayReq({ pay_req: req.query.invoice }, function (err, info) {
    if (err) return errorNotAValidInvoice(res);
    res.send(info);
  });
});

router.get('/checkrouteinvoice', async function (req, res) {
  logger.log('/checkrouteinvoice', [req.id]);
  let u = new User(redis, bitcoinclient, lightning);
  if (!(await u.loadByAuthorization(req.headers.authorization))) {
    return errorBadAuth(res);
  }

  if (!req.query.invoice) return errorGeneralServerError(res);

  // at the momment does nothing.
  // TODO: decode and query actual route to destination
  lightning.decodePayReq({ pay_req: req.query.invoice }, function (err, info) {
    if (err) return errorNotAValidInvoice(res);
    res.send(info);
  });
});

router.get('/queryroutes/:source/:dest/:amt', async function (req, res) {
  logger.log('/queryroutes', [req.id]);

  let request = {
    pub_key: req.params.dest,
    use_mission_control: true,
    amt: req.params.amt,
    source_pub_key: req.params.source,
  };
  lightning.queryRoutes(request, function (err, response) {
    console.log(JSON.stringify(response, null, 2));
    res.send(response);
  });
});

router.get('/getchaninfo/:chanid', async function (req, res) {
  logger.log('/getchaninfo', [req.id]);

  if (lightningDescribeGraph && lightningDescribeGraph.edges) {
    for (const edge of lightningDescribeGraph.edges) {
      if (edge.channel_id == req.params.chanid) {
        return res.send(JSON.stringify(edge, null, 2));
      }
    }
  }
  res.send('');
});

router.post('/getcardkeys', async function (req, res) {
  logger.log('/getcardkeys', [req.id]);
  
  let u = new User(redis, bitcoinclient, lightning);
  if (!(await u.loadByAuthorization(req.headers.authorization))) {
    return errorBadAuth(res);
  }
  logger.log('/getcardkeys', [req.id, 'userid: ' + u.getUserId()]);

  //talk to the boltcard service and create a new card. get the keys.

  let card_name = req.body.card_name;
  var tx_max = 1000;
  var day_max = 10000;
  var enable = 'true';
  var uid_privacy = 'false';
  var allow_neg_bal = 'false';


  var query = `card_name=${card_name}&tx_max=${tx_max}&day_max=${day_max}&enable=${enable}&uid_privacy=${uid_privacy}&allow_neg_bal=${allow_neg_bal}`;
  logger.log('/getcardkeys', `${config.boltcardservice.url}/createboltcard?${query}`);

  //call create bolt card
  try {
    var createReqResponse = await rp({uri: `${config.boltcardservice.url}/createboltcard?${query}`, json: true});

    logger.log('/getcardkeys CREATE RESPONSE', [createReqResponse]);
    if(createReqResponse.status == "ERROR") {
      return res.send({
        error: true,
        code: 6,
        message: createReqResponse.reason,
      });
    }
    if(createReqResponse.url) {
      //get the actual keys
      logger.log('/getcardkeys NEW GET', createReqResponse.url);
      let cardUrl = new URL(createReqResponse.url);
      // var newCardUrl = new URL(cardUrl);
      let newCardUrl = cardUrl;
      if(config.boltcardservice.service_url) {
        newCardUrl = config.boltcardservice.service_url+cardUrl.pathname+cardUrl.search;
        logger.log('/getcardkeys NEW GET URL for docker', newCardUrl);
      }

      var keys = await rp({uri: newCardUrl, json: true});
      logger.log('/getcardkeys NEW GET RESPONSE', [keys]);
      return res.send(keys);
    }
    return res.send({
      error: true,
      code: 6,
      message: 'not able to connect to bolt card service',
    });


  } catch (error) {
    logger.log('/getcardkeys ERROR RESPONSE', error.message);

    return res.send({
      error: true,
      code: 6,
      message: error.message,
    });
  }

});

router.post('/wipecard', async function (req, res) {
  logger.log('/wipecard', [req.id]);
  
  let u = new User(redis, bitcoinclient, lightning);
  if (!(await u.loadByAuthorization(req.headers.authorization))) {
    return errorBadAuth(res);
  }

  let card_name = req.body.card_name;
  logger.log('/wipecard', [req.id, 'userid: ' + u.getUserId(), ';card_name'+card_name]);

  var query = `card_name=${card_name}`;

  //talk to the boltcard service and wipe a card. get the keys.
  try {
    var wipeReqResponse = await rp({uri: `${config.boltcardservice.url}/wipeboltcard?${query}`, json: true});

    if(wipeReqResponse.status == "ERROR") {
      return res.send({
        error: true,
        code: 6,
        message: wipeReqResponse.reason,
      });
    }
    return res.send(wipeReqResponse);

  } catch (error) {
    return res.send({
      error: true,
      code: 6,
      message: error.message,
    });
  }

})

router.post('/getcard', async function (req, res) {
  logger.log('/getcard', [req.id]);
  
  let u = new User(redis, bitcoinclient, lightning);
  if (!(await u.loadByAuthorization(req.headers.authorization))) {
    return errorBadAuth(res);
  }

  let card_name = req.body.card_name;
  logger.log('/getcard', [req.id, 'userid: ' + u.getUserId(), ';card_name'+card_name]);

  var query = `card_name=${card_name}`;

  //talk to the boltcard service and find the card
  try {
    var response = await rp({uri: `${config.boltcardservice.url}/getboltcard?${query}`, json: true});

    if(response.status == "ERROR") {
      return res.send({
        error: true,
        code: 6,
        message: response.reason,
      });
    }
    return res.send(response);

  } catch (error) {
    return res.send({
      error: true,
      code: 6,
      message: error.message,
    });
  }
})

router.post('/setdisablecard', async function (req, res) {
  logger.log('/setdisablecard', [req.id, 'userid: ' + u.getUserId()]);
  let status = req.body.disable_card;

  u.setCardDisabled(status);
  //@todo call the bolt service disable card API call.
  
  res.send({disable_card_set: status});
});

router.post('/updatecard', async function (req, res) {
  logger.log('/updatecard', [req.id]);
  // u.setCardDisabled(status);
  
  let u = new User(redis, bitcoinclient, lightning);
  if (!(await u.loadByAuthorization(req.headers.authorization))) {
    return errorBadAuth(res);
  }
  logger.log('/updatecard', [req.id, 'userid: ' + u.getUserId()]);

  let tx_max = req.body.tx_max;
  let enable = req.body.enable;
  let card_name = req.body.card_name;
  let day_max = req.body.day_max;
  logger.log('/updatecard', [req.body]);

  var query = `card_name=${card_name}&enable=${enable}&tx_max=${tx_max}&day_max=${day_max}`;

  //talk to the boltcard service and update the card
  try {
    var response = await rp({uri: `${config.boltcardservice.url}/updateboltcard?${query}`, json: true});

    if(response.status == "ERROR") {
      return res.send({
        error: true,
        code: 6,
        message: response.reason,
      });
    }
    return res.send(response);

  } catch (error) {
    return res.send({
      error: true,
      code: 6,
      message: error.message,
    });
  }
  
});

module.exports = router;

// ################# HELPERS ###########################

function errorBadAuth(res) {
  return res.send({
    error: true,
    code: 1,
    message: 'bad auth',
  });
}

function errorNotEnougBalance(res) {
  return res.send({
    error: true,
    code: 2,
    message: 'not enough balance. Make sure you have at least 1% reserved for potential fees',
  });
}

function errorNotAValidInvoice(res) {
  return res.send({
    error: true,
    code: 4,
    message: 'not a valid invoice',
  });
}

function errorLnd(res) {
  return res.send({
    error: true,
    code: 7,
    message: 'LND failue',
  });
}

function errorGeneralServerError(res) {
  return res.send({
    error: true,
    code: 6,
    message: 'Something went wrong. Please try again later',
  });
}

function errorBadArguments(res) {
  return res.send({
    error: true,
    code: 8,
    message: 'Bad arguments',
  });
}

function errorTryAgainLater(res) {
  return res.send({
    error: true,
    code: 9,
    message: 'Your previous payment is in transit. Try again in 5 minutes',
  });
}

function errorPaymentFailed(res) {
  return res.send({
    error: true,
    code: 10,
    message: 'Payment failed. Does the receiver have enough inbound capacity?',
  });
}

function errorSunset(res) {
  return res.send({
    error: true,
    code: 11,
    message: 'This LNDHub instance is not accepting any more users',
  });
}

function errorSunsetAddInvoice(res) {
  return res.send({
    error: true,
    code: 11,
    message: 'This LNDHub instance is scheduled to shut down. Withdraw any remaining funds',
  });
}


{"payment_error":"",
"payment_preimage":
{"type":"Buffer",
"data":[223,80,235,118,68,219,6,62,9,134,64,136,105,204,12,27,89,185,112,64,10,15,133,71,127,208,60,234,150,199,20,204]},
"payment_route":{
  "hops":[{"custom_records":{},"chan_id":"850787804143157249","chan_capacity":"1000000","amt_to_forward":"201","fee":"1","expiry":780083,"amt_to_forward_msat":"201060","fee_msat":"1040","pub_key":"03d2d9b865127074632a6b8f8e67c977e9618b55ba0e7d9c005011549bd6ecc302","tlv_payload":true,"mpp_record":null},
    {"custom_records":{},"chan_id":"839140677364023297","chan_capacity":"5000000","amt_to_forward":"201","fee":"0","expiry":780043,"amt_to_forward_msat":"201000","fee_msat":"60","pub_key":"035e4ff418fc8b5554c5d9eea66396c227bd429a3251c8cbc711002ba215bfc226","tlv_payload":true,"mpp_record":null},
    {"custom_records":{},"chan_id":"856948367666970625","chan_capacity":"16777215","amt_to_forward":"200","fee":"1","expiry":780003,"amt_to_forward_msat":"200000","fee_msat":"1000","pub_key":"031015a7839468a3c266d662d5bb21ea4cea24226936e2864a7ca4f2c3939836e0","tlv_payload":true,"mpp_record":null},
    {"custom_records":{},"chan_id":"17592186044416006758","chan_capacity":"200","amt_to_forward":"200","fee":"0","expiry":780003,"amt_to_forward_msat":"200000","fee_msat":"0","pub_key":"036399b660a6760f449762abd78cdb35ed91a436b4eec4fab0c3c5a177a4466015","tlv_payload":true,"mpp_record":{"total_amt_msat":"200000","payment_addr":{"type":"Buffer","data":[254,170,121,202,248,24,21,119,234,121,242,171,138,73,158,172,161,188,127,210,114,182,33,22,224,191,93,185,75,229,224,24]}}}],
  "total_time_lock":780123,"total_fees":2,"total_amt":"202","total_fees_msat":"2100","total_amt_msat":"202100"},"payment_hash":{"type":"Buffer","data":[218,61,131,173,96,82,178,106,139,20,18,191,155,29,116,61,222,186,209,89,94,179,2,169,37,228,158,221,18,111,151,234]},"pay_req":"lnbc2u1pjqj5d8pp5mg7c8ttq22ex4zc5z2lek8t58h0t452et6es92f9uj0d6yn0jl4qdr9yp7q5smjd9khxmmwyppxzapq0ssxyun9v4ar5te0wpex7enfd3j476tdv9nk20mpde5k6ctv84pxzapxvdhkcmmj84phy6tdwdhkucqzpgxqrrssrzjqvgptfurj3528snx6e3dtwepafxw5fpzdymw9pj20jj09sunnqmwpapyqqqqqqq6vcqqqqlgqqqqqqgq9qsp5l648njhcrq2h06ne724c5jv74jsmcl7jw2mzz9hqhawmjjl9uqvq9qyyssqz8ww8nr7xxrxcwmwzy927345zqe5cd67hh4jr3xvpc8mm55msqrnup5yxzzzg4a8r2zdefger7a4ezkydwm7c4wy9eyhfa6lhamn9ncq4e2wkm","decoded":{"route_hints":[{"hop_hints":[{"node_id":"031015a7839468a3c266d662d5bb21ea4cea24226936e2864a7ca4f2c3939836e0","chan_id":"17592186044416006758","fee_base_msat":1000,"fee_proportional_millionths":1,"cltv_expiry_delta":40}]}],"features":{"9":{"name":"tlv-onion","is_required":false,"is_known":true},"14":{"name":"payment-addr","is_required":true,"is_known":true},"17":{"name":"multi-path-payments","is_required":false,"is_known":true}},"destination":"036399b660a6760f449762abd78cdb35ed91a436b4eec4fab0c3c5a177a4466015","payment_hash":"da3d83ad6052b26a8b1412bf9b1d743ddebad1595eb302a925e49edd126f97ea","num_satoshis":"200","timestamp":"1678332327","expiry":"3600","description":" |\nCrimson Bat | breez://profile_image?animal=Bat&color=Crimson","description_hash":"","fallback_addr":"","cltv_expiry":"40","payment_addr":{"type":"Buffer","data":[254,170,121,202,248,24,21,119,234,121,242,171,138,73,158,172,161,188,127,210,114,182,33,22,224,191,93,185,75,229,224,24]},"num_msat":"200000"}}
