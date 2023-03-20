const debug = require('debug')('auth-example:server');
const path = require("path");
const http = require('http');
const express = require('express');
const session = require("express-session");
const logger = require('morgan');
const createError = require('http-errors');
const cookieParser = require('cookie-parser');
const openidClient = require("openid-client");
const Stripe = require('stripe');

require('express-async-errors');

require("dotenv").config();

const config = {
    "BASE_URL": process.env.BASE_URL || "http://localhost:8090",
    "RETURN_URL": process.env.RETURN_URL || "http://localhost:8090/confirmation",
    "STATIC_DIR": process.env.STATIC_DIR || path.join(__dirname, "static"),
    "SESSION_SECRET": process.env.SESSION_SECRET,
    "VV_ISSUER_URL": process.env.VV_ISSUER_URL,
    "VV_CLIENT_ID": process.env.VV_CLIENT_ID,
    "VV_CLIENT_SECRET": process.env.VV_CLIENT_SECRET,
    "STRIPE_API_PK": process.env.STRIPE_API_PK,
    "STRIPE_API_SK": process.env.STRIPE_API_SK,
};

// Key needs to change during dev while removing keys regularly or calls
// return a hard to figure out 404.
const IDEMPOTENCY_KEY = "vv_customers_create_by_sub_";
// const IDEMPOTENCY_KEY = "00_vv_customers_create_by_sub_";


const stripe = Stripe.Stripe(config.STRIPE_API_SK, {
    maxNetworkRetries: 1,
    timeout: 2000,
    telemetry: false,
});

const oidcCallbackUrl = new URL('/auth/callback', config.BASE_URL).toString();
const oidcLogoutUrl = new URL('/auth/logout', config.BASE_URL).toString();
let _oidcClient;
function getOidcClient() {
    return new Promise((resolve, reject) => {
        if (_oidcClient) {
            resolve(_oidcClient);
            return;
        }

        const cbResolve = (iss) => {
            _oidcClient = new iss.Client({
                client_id: config.VV_CLIENT_ID,
                client_secret: config.VV_CLIENT_SECRET,
                redirect_uris: [config.BASE_URL + "/auth/callback"],
                response_types: ['code'],
            });
            resolve(_oidcClient);
        }
        const cbError = (err) => {
            reject(err);
        }
        openidClient.Issuer.discover(config.VV_ISSUER_URL)
            .then(cbResolve)
            .catch(cbError);
    });
}

const app = express();
app.set('view engine', 'ejs');
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(session({
    secret: config.SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
    httpOnly: true,
    name: "authsess",
    cookie: {
        secure: false,
        sameSite: 'lax',
    },
}));
app.use("/static", express.static(config.STATIC_DIR));

function returnToApp(req, res, params) {
    delete req.session.stripe;

    const u = new URL(config.RETURN_URL);
    for (const [key, val] of Object.entries(params)) {
        u.searchParams.set(key, val);
    }
    res.redirect(u.toString());
}

function checkMetadata(req, res, metadata) {
    if (!req.session.userinfo) {
        throw new Error("access_denied_not_logged_in");
    }
    if (!metadata.hasOwnProperty('vv_sub')) {
        throw new Error("access_denied_missing_metadata_vv_sub");
    }
    if (metadata.vv_sub !== req.session.userinfo.sub) {
        throw new Error("access_denied_vv_sub_mismatch");
    }
}

const withAuth = async (req, res, next) => {
    if (!req.session.userinfo) {
        req.session.returnPath = req.path;
        res.redirect('/auth/login');
        return;
    }
    return next();
};

const withStripeReset = async (req, res, next) => {
    req.session.stripe = {};
    return next();
};

const withStripeCustomer = async (req, res, next) => {
    const vvSub = req.session.userinfo.sub;
    const custQuery = "metadata['vv_sub']:'" + vvSub + "'";
    const custRes = await stripe.customers.search({
        query: custQuery,
    }).autoPagingToArray({ limit: 4 });

    if (!req.session.stripe) {
        req.session.stripe = {}
    }
    if (custRes.length > 0) {
        req.session.stripe.customer_id = custRes[0].id;
        console.log("syncCustomer found:", custRes[0]);
        return next();
    }

    const customer = await stripe.customers.create({
        name: req.session.userinfo.name,
        email: req.session.userinfo.email,
        metadata: {
            "vv_sub": req.session.userinfo.sub,
        },
    }, {
        idempotencyKey: IDEMPOTENCY_KEY + vvSub,
    });


    req.session.stripe.customer_id = customer.id;
    return next();
};

app.get('/throw', (req, res) => {
    throw new Error('BROKEN');
});

app.get('/throwasync', async (req, res) => {
    throw new Error('BROKEN');
});

// Fake route for when there is no real return URL set.
app.get('/confirmation',
    withAuth,
    async (req, res) => {
        console.log("session", req.session);

        res.status(200).send("Set RETURN_URL for customization");
    });

app.get('/billing/portal',
    withAuth,
    withStripeReset,
    withStripeCustomer,
    async (req, res) => {
        const customerId = req.session.stripe.customer_id;
        const returnUrl = config.BASE_URL + "/billing/portal/success"
        const portalOpts = {
            return_url: returnUrl,
            customer: customerId,
        }

        const session = await stripe.billingPortal.sessions.create(portalOpts);
        req.session.stripe.portal_session_id = session.id;

        res.redirect(session.url);
    });

app.get('/billing/portal/success',
    withAuth,
    async (req, res) => {
        const params = {
            'result': 'success',
            'result_type': 'portal',
        }
        return returnToApp(req, res, params);
    });

app.get('/billing/checkout/:price_id',
    withAuth,
    withStripeReset,
    withStripeCustomer,
    async (req, res) => {
        const price = await stripe.prices.retrieve(req.params.price_id);
        if (!price.active) {
            throw new Error("price not active");
        }

        const customerId = req.session.stripe.customer_id;
        const metadata = {
            "vv_sub": req.session.userinfo.sub,
        }

        const baseUrl = config.BASE_URL + "/billing/checkout"
        const checkoutOpts = {
            success_url: baseUrl + "/{CHECKOUT_SESSION_ID}/success",
            cancel_url: baseUrl + "/{CHECKOUT_SESSION_ID}/cancel",
            line_items: [
                {
                    price: req.params.price_id,
                    quantity: 1,
                },
            ],
            customer: customerId,
            metadata: metadata,
        }
        if (price.type === "recurring") {
            checkoutOpts.mode = 'subscription';
            checkoutOpts.subscription_data = {
                metadata: metadata,
            }
        } else {
            checkoutOpts.mode = 'payment';
            checkoutOpts.payment_intent_data = {
                metadata: metadata,
            }
        }

        const session = await stripe.checkout.sessions.create(checkoutOpts);
        res.redirect(session.url);
    });

app.get('/billing/checkout/:session/success',
    withAuth,
    async (req, res, next) => {
        return handleSessionComplete(req, res, next, "success");
    });

app.get('/billing/checkout/:session/cancel',
    withAuth,
    async (req, res, next) => {
        return handleSessionComplete(req, res, next, "canceled");
    });

async function handleSessionComplete(req, res, next, result) {
    const sessionId = req.params.session
    const session = await stripe.checkout.sessions.retrieve(
        req.params.session,
    );
    checkMetadata(req, res, session.metadata);

    const params = {
        'result': 'canceled',
        'result_type': 'checkout',
        'stripe_customer_id': session.customer,
        'stripe_checkout_session_id': session.id,
    }

    const lineItems = await lineItemsFromSession(req, res, next, session);
    if (lineItems.length === 0) {
        return returnToApp(req, res, params);
    }

    const item = lineItems[0];
    if (item.price) {
        params['stripe_price_id'] = item.price.id;
        params['stripe_product_id'] = item.price.product;
    }

    try {
        await stripe.checkout.sessions.expire(sessionId);
    } catch (err) {
        // drop it, we don't care
    }
    return returnToApp(req, res, params);
}

async function lineItemsFromSession(req, res, next, session) {
    try {
        const lineItems = [];
        const res = stripe.checkout.sessions.listLineItems(session.id);
        for await (
            const lineItem of res
        ) {
            lineItems.push(lineItem);
        }
        return lineItems;
    } catch (err) {
        return next(err);
    }
}

app.get('/', (req, res) => {
    console.log(req.session);

    const data = {
        user: req.session.userinfo,
        user_json: JSON.stringify(req.session.userinfo, null, " "),
        oidc: {
            issuer_url: config.VV_ISSUER_URL,
        },
    };
    getOidcClient().then((oidcClient) => {
        res.render('index', data);
    }).catch((err) => {
        data.oidc.error = err;
        res.render('index', data);
    });
});

// /login just redirects to /auth/login. But it could contain any app specific
// logic or a confirmation page that shows a login button.
app.get('/login', (req, res) => {
    res.redirect('/auth/login');
});

// /auth/login kicks off the OIDC flow by redirecting to Vault Vision. Once
// authentication is complete the user will be returned to /auth/callback.
app.get('/auth/login', (req, res) => {
    getOidcClient().then((oidcClient) => {
        const gens = openidClient.generators;
        const nonce = gens.nonce();
        const state = gens.state();
        const codeVerifier = gens.codeVerifier();
        const codeChallenger = gens.codeChallenge(codeVerifier);

        req.session.code_verifier = codeVerifier;
        req.session.nonce = nonce;
        req.session.state = state;

        const redir = oidcClient.authorizationUrl({
            scope: 'openid email profile',
            resource: oidcCallbackUrl,
            code_challenge: codeChallenger,
            code_challenge_method: 'S256',
            nonce: nonce,
            state: state,
        });
        res.redirect(redir);
    }).catch((err) => {
        res.redirect('/');
    });
});

// Once Vault Vision authenticates a user they will be sent here to complete
// the OIDC flow.
app.get('/auth/callback', (req, res, next) => {
    getOidcClient().then((oidcClient) => {
        const oidcParams = oidcClient.callbackParams(req);
        oidcClient.callback(oidcCallbackUrl, oidcParams, {
            code_verifier: req.session.code_verifier,
            state: req.session.state,
            nonce: req.session.nonce,
        }).then((tokenSet) => {

            req.session.sessionTokens = tokenSet;
            req.session.claims = tokenSet.claims();

            const returnPath = req.session.returnPath;
            const finish = function () {
                if (returnPath) {
                    delete req.session.returnPath;
                    res.redirect(returnPath);
                    return;
                }
                res.redirect('/');
            };

            if (tokenSet.access_token) {
                oidcClient.userinfo(tokenSet.access_token).then((userinfo) => {

                    req.session.regenerate(function (err) {
                        if (err) {
                            return next(err);
                        }

                        req.session.userinfo = userinfo;
                        req.session.save(function (err) {
                            if (err) {
                                return next(err);
                            }
                            return finish();
                        });
                    });
                });
            } else {
                return finish();
            }
        });
    }).catch((err) => {
        console.log(err);
        res.redirect('/');
    });
});

// Logout clears the cookies and then sends the users to Vault Vision to clear
// the session, then Vault Vision will redirect the user to /auth/logout.
app.get('/logout', (req, res, next) => {
    req.session.userinfo = null;
    req.session.stripe = null;

    req.session.save(function (err) {
        if (err) {
            return next(err);
        }
        req.session.regenerate(function (err) {
            if (err) {
                return next(err);
            }

            const u = new URL('/logout', config.VV_ISSUER_URL);
            u.searchParams.set('client_id', config.VV_CLIENT_ID);
            u.searchParams.set('return_to', oidcLogoutUrl);
            res.redirect(u.toString());
        });
    });
});

// Once Vault Vision clears the users session, they return to this route.
app.get('/auth/logout', (req, res) => {
    res.redirect('/');
});

// /settings just redirects to /auth/settings. But it could contain any app 
// specific logic or a confirmation page that shows a settings button.
app.get('/settings', (req, res) => {
    res.redirect('/auth/settings');
});

// /auth/settings redirects to the Vault Vision settings page so users can
// manage their email, password, social logins, webauthn credentials and more.
app.get('/auth/settings', (req, res) => {
    res.redirect(config.VV_ISSUER_URL + '/settings');
});

app.use(function (req, res, next) {
    next(createError(404));
});

app.use(function (err, req, res, next) {
    console.debug("error", err);

    const params = {
        'result': 'error',
        'message': err.message,
        'error': req.app.get('env') === 'development' ? err : {},
    };
    return returnToApp(req, res, params);
});

function runServer() {
    const server = http.createServer(app);
    server.on('error', function (error) {
        if (error.syscall !== 'listen') {
            throw error;
        }

        var bind = typeof port === 'string'
            ? 'Pipe ' + port
            : 'Port ' + port;

        // handle specific listen errors with friendly messages
        switch (error.code) {
            case 'EACCES':
                console.error(bind + ' requires elevated privileges');
                process.exit(1);
                break;
            case 'EADDRINUSE':
                console.error(bind + ' is already in use');
                process.exit(1);
                break;
            default:
                throw error;
        }
    });
    server.on('listening', function () {
        var addr = server.address();
        var bind = typeof addr === 'string'
            ? 'pipe ' + addr
            : 'port ' + addr.port;
        debug('Listening on ' + bind);
    });

    const baseUrl = new URL(config.BASE_URL);
    server.listen(parseInt(baseUrl.port, 10), baseUrl.hostname);
}

runServer();
