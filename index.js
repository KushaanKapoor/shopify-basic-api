const dotenv = require("dotenv").config();
const express = require("express");
const app = express();

const crypto = require("crypto");
const querystring = require('querystring');

const cookie = require("cookie");
const request = require('request-promise');

const nonce = require("nonce")();

const apiKey = process.env.SHOPIFY_API_KEY;
const apiSecret = process.env.SHOPIFY_API_SECRET_KEY;

const scopes = "write_products";

const forwardingAddress = process.env.HOSTED_URL; //replace with HTTPS forwarding address

// app.get("/", (req, res) => {
//   res.send("Hello world!");
// });


app.get('/shopify', (req, res) => {

    const shop = req.query.shop;
    if(shop) 
    {
        const state = nonce();
        const redirectUri = forwardingAddress + '/shopify/api/callback';
        const installUrl = 'https://' + shop + '/admin/oauth/authorize?client_id=' + apiKey +
        '&scope=' + scopes +
        '&state=' + state + 
        '&redirect_uri=' + redirectUri;

        res.cookie('state', state); //crypt and decrypt it later.
        res.redirect(installUrl);
    }
     else {
         return res.status(400).send('Missing Shop Parameters, Please Add ?shop=your-dev-store.shopify.com to your request');
     }

})


app.get('/shopify/api/callback', (req, res) => {

    const {
        shop, hmac, code, state
    } = req.query;

    const stateCookie = cookie.parse(req.headers.cookie).state;

    if(state !== stateCookie)
    {
        return res.status(403).send('Request cannot be verified');
    }
    
    if(shop && hmac && code) {
        const map = Object.assign({}, req.query);
        delete map['hmac'];
        console.log('map', map);
        const message = querystring.stringify(map);
        const generateHash = crypto.createHmac('sha256', apiSecret).update(message).digest('hex');

        if(generateHash !== hmac)
        {
            return res.status(400).send('HMAC validation failed');
        }

        // return res.status(200).send('HMAC validated');
        const accessTokenRequestUrl = 'https://' + shop + '/admin/oauth/access_token';
        const accessTokenPayload = {
            client_id: apiKey,
            client_secret: apiSecret,
            code
        };

        request.post(accessTokenRequestUrl, {json: accessTokenPayload }).then((accessTokenResponse) => {
            const accessToken = accessTokenResponse.access_token;

            res.cookie('auth', accessToken)
            res.cookie('shop', shop)
            res.status(200).send('Access token recieved!');
        }).catch((err) => {
            res.status(err.statusCode).send(err.error.error_description);
        })
    }
    else {
        return res.status(400).send('Required parameters missing');
    }
});

app.get('/shopify/api/getAllProducts', (req, res) => {

    const token = cookie.parse(req.headers.cookie).auth;
    const shop = cookie.parse(req.headers.cookie).shop;
    console.log('token', token);
    
    try {

        const apiRequestUrl = 'https://' + shop + '/admin/products.json';
        
        const apiRequestHeader = {
            'X-Shopify-Access-Token': token
        };
        
        request.get(apiRequestUrl, {headers: apiRequestHeader }).then((apiResponse) => {
            res.status(200).send(apiResponse);
        }).catch((err) => {
          res.status(err.statusCode).send(err.error.error_description);
        })
    } catch (err)
    {
        console.log('err', err);
        return res.status(400).send(err.error.error_description);
    }
        
    });

    app.get('/shopify/api/getShopData', (req, res) => {

        const token = cookie.parse(req.headers.cookie).auth;
        const shop = cookie.parse(req.headers.cookie).shop;
        console.log('token', token);
        
        try {
    
            const apiRequestUrl = 'https://' + shop + '/admin/shop.json';
            
            const apiRequestHeader = {
                'X-Shopify-Access-Token': token
            };
            
            request.get(apiRequestUrl, {headers: apiRequestHeader }).then((apiResponse) => {
                res.status(200).send(apiResponse);
            }).catch((err) => {
              res.status(err.statusCode).send(err.error.error_description);
            })
        } catch (err)
        {
            console.log('err', err);
            return res.status(400).send('Error');
        }
            
        });
    
app.listen(3000, () => {
  console.log("listening to port 3000");
});
