var express = require('express');
var router = express.Router();
var config = require('../config/config')
var moment = require("moment");
var request = require('request');
var iconv = require('iconv-lite');
var crypto = require('crypto');
var fs = require('fs');


/* 模拟:进入页面 */
router.get('/', function(req, res, next) {

    // 导入变量
    var app_id = config.app_id;
    var redirect_uri = config.redirect_uri;
    // 获取原来url
    var origin_url = req.originalUrl;
    var param_url = encodeURIComponent(redirect_uri + "origin_url=" + encodeURIComponent(origin_url));
    var url = "https://openauth.alipay.com/oauth2/publicAppAuthorize.htm?app_id=" + app_id + "&scope=auth_base&redirect_uri=" + param_url;
    res.redirect(url);
});




/*模拟:口碑支付宝回调*/
route.get('/zhifubaoRetrun', function(req, res, next) {
    // 获取auth_code
    var origin_url = req.query.origin_url;
    var auth_code = req.query.auth_code;
    var app_id = req.query.app_id;
    // 校验参数
    if (auth_code == undefined || app_id == undefined) {
        // 跳转到失败页面
        return;
    }


    // 使用auth_code换取接口access_token及用户userId
    var sign = "";
    var url = "https://openapi.alipay.com/gateway.do";
    var stamp = moment(new Date()).format('YYYY-MM-DD HH:mm:ss');
    //提前排好顺序
    var post_data = {
        app_id: app_id,
        charset: "GBK",
        code: auth_code,
        grant_type: "authorization_code",
        method: "alipay.system.oauth.token",
        sign: sign,
        sign_type: "RSA",
        timestamp: stamp,
        version: "1.0"
    };
    post_data.sign = createSign(post_data);

    request.post({
        url: url,
        formData: post_data,
        encoding: null
    }, function(err, httpResponse, body) {
        //出错
        if (err) {
            res.render('error', {
                title: 'error',
                message: '授权失败'
            });
            return;
        }
        //验签
        var verifySign = verifySign(body);
        if (!verifySign) {
        	  res.render('error', {
                title: 'error',
                message: '验签失败,可能为伪造数据!'
            });
            return;
        };
        //TODO:自己程序内部逻辑,调用自己登录接口等.


    });


});

// 生成RSA密钥
function createSign(post_data) {
    var sign = '';
    var str = '';
    for (var key in post_data) {
        if (key == 'sign') {
            continue;
        }
        if (str == '') {
            str += key + '=' + post_data[key]
        } else {
            str += '&' + key + '=' + post_data[key]
        }
    }
    //读取自己的私钥进行加密
    var privatePem = fs.readFileSync('koubeiprikey.pem');
    var key = privatePem.toString();
    var data = iconv.encode(str, 'GBK');
    var signf = crypto.createSign('RSA-SHA1');
    signf.update(data);
    sign = signf.sign(key, 'base64');
    return sign;

}

// 验证返回密钥
function verifySign(body) {
    //验签
    var encodedBody = iconv.decode(body, 'GBK');

    var jsonData = JSON.parse(encodedBody);
    var data = jsonData.alipay_system_oauth_token_response;

    var str = '';
    for (var key in data) {
        if (key == 'user_id') {
            continue;
        }
        if (str == '') {
            str += key + '=' + data[key]
        } else {
            str += '&' + key + '=' + data[key]
        }
    }

    //支付宝公钥
    var publicPem = fs.readFileSync('alipaypub.key');
    
    var pubkey = publicPem.toString();

    //转为GBK
    var gbkDataBuf = iconv.encode(str, 'GBK');

    var verify = crypto.createVerify('RSA-SHA1');

    verify.update(gbkDataBuf);

    //验签
    var verifyResult = verify.verify(pubkey, jsonData.sign, 'base64');

}

module.exports = router;
