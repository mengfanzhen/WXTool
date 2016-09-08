import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.alibaba.fastjson.JSONObject;


/**
 * 微信工具类-获取签名  <br/>
 * 微信js-sdk：http://mp.weixin.qq.com/wiki/7/aaa137b55fb2e0456bf8dd9148dd613f.html <br/>
 * 不支持企业号
 * 
 * @author LFG
 * @version 2015-4-16 下午2:58:37 类说明
 */
public class WxTool {
	private static Log log = LogFactory.getLog(WxTool.class);

//	public static String appId = "wxfbbca0532240661b";
//	public static String appsecret = "89577de0bc20ae98d38046e622e14978";
	private static String appId;
	private static String appsecret;
	private static String access_token;
	private static String jsapi_ticket;
	private static long cacheTime = 0;// 记录时间，超时7200s重新获取jsapi_ticket，
	private static long threadId = -1;

	/**
	 * 
	 * 方法描述: 微信获取签名，超时重新获取
	 * 
	 * @param url 页面的url
	 * @param appConfig 可选参数，格式 "appid,appsecret"，如 "wxfbbca0532240661b,89577de0bc20ae98d38046e622e14978"
	 * 会初始化appid,appsecret，如果已经设置过了，最好别再传。<br/>
	 * WxTool.isAppConfigSet() 返回是否已经设置过appid,appsecret
	 * 
	 * @return Map<String,String>
	 * @author lfg 2016年6月4日
	 *
	 */
	public static Map<String, String> getSignature(String url,String ...appConfig)throws RuntimeException {
		
		if(appConfig.length != 1){
			if(!isAppConfigSet())
				throw new RuntimeException("微信的appId和appsecret未设置!");
		}else{
			try {
				String[] tmp = appConfig[0].split(",");
				appId = tmp[0];
				appsecret = tmp[1];
			} catch (Exception e) {
				throw new RuntimeException("appId和appsecret格式错误!");
			}
		}
		
		if (threadId == -1) {
			synchronized(WxTool.class){ //独立线程获取JsapiTicket,d多线程锁住
				if (threadId == -1) {
					getJsapiTicket(); //第一次初始化，线程是异步的，需要先获取ticket一次
					new Thread(){
						public void run() {
							threadId = Thread.currentThread().getId();
							while(true){
								try {
									if (System.currentTimeMillis() / 1000 - cacheTime >= 7000){
										getJsapiTicket();
									}
									Thread.sleep(7000*1000);//7000s挂起
								} catch (Exception e) {
									log.error("Thread--Exception", e);
									try {
										Thread.sleep(10*1000);//异常，十秒重试
									} catch (InterruptedException e1) {
										e1.printStackTrace();
									}
								}
								
							}
						};
					}.start();
				}
				
			}
		}
		
		String nonceStr = getRandomString(20);
		String timestamp = System.currentTimeMillis() / 1000 + "";
		String tmp = "jsapi_ticket=" + jsapi_ticket + "&noncestr=" + nonceStr
				+ "&timestamp=" + timestamp + "&url=" + url;

		if (log.isDebugEnabled())
			log.debug("获取签名,tmp=" + tmp);
		
		MessageDigest md = null;
		String tmpStr = null;
		try {
			md = MessageDigest.getInstance("SHA-1");
			// 将字符串进行sha1加密
			byte[] digest = md.digest(tmp.getBytes());
			tmpStr = byteToStr(digest);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		HashMap<String, String> map = new HashMap<String, String>();
		map.put("nonceStr", nonceStr);
		map.put("timestamp", timestamp);
		map.put("signature", tmpStr);
		map.put("appId", appId);
		
		if (log.isDebugEnabled())
			log.debug("获取签名,map=" + map);
		
		return map;
	}

	/**
	 * 获取jsapi_ticket 全局返回码说明：http://mp.weixin.qq.com/wiki/17/fa4e1434e57290788bde25603fa2fcbd.html
	 * 
	 * @return
	 */
	private static String getJsapiTicket() {

		String message = null;
		String message2 = null;
		if(appId == null || "".equals(appId)){
			if (log.isDebugEnabled())
				log.debug("获取appId失败,请配置！");
			return null;
		}
		
		
		
		
		
		// 步骤一，获取access_token
		String url = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid="
				+ appId + "&secret=" + appsecret;
		if (log.isDebugEnabled())
			log.debug("获取access_token,url=" + url);

		JSONObject jo =  (JSONObject) JSONObject.parse(http(url));
		
		String access_token = (String) jo.get("access_token");
		if (access_token != null && !"".equals(access_token)) {
			WxTool.access_token = access_token;
			message = "获取access_token成功！access_token=" + access_token;
		} else if (!"0".equals((String) jo.get("errcode"))) {
			message = "获取access_token失败！" + jo.toString();
		} else {
			message = "其它错误！" + jo.toString();
		}
		if (log.isDebugEnabled())
			log.debug("获取access_token,message=" + message);

		// 步骤二，获取jsapi_ticket
		url = "https://api.weixin.qq.com/cgi-bin/ticket/getticket?access_token="
				+ access_token + "&type=jsapi";
		if (log.isDebugEnabled())
			log.debug("获取jsapi_ticket,url=" + url);

		jo = (JSONObject) JSONObject.parse(http(url));

		int errcode = (Integer) jo.get("errcode");
		String ticket = (String) jo.get("ticket");

		if (errcode == 0) {
			WxTool.jsapi_ticket = ticket;
			message2 = "获取jsapi_ticket成功！jsapi_ticket=" + ticket;
		} else {
			message2 = "获取jsapi_ticket失败！" + jo.toString();
		}
		if (log.isDebugEnabled())
			log.debug("获取jsapi_ticket,message2=" + message2);

		cacheTime = System.currentTimeMillis() / 1000;

		return null;
	}

	/**
	 * httpget方法
	 * 
	 * @param url
	 * @return
	 */
	private static String http(String url) {
		URL u = null;
		HttpURLConnection con = null;
		try {
			SSLInit();
			u = new URL(url);
			con = (HttpURLConnection) u.openConnection();
			con.setRequestMethod("GET");
			con.setConnectTimeout(10000);
			con.connect();
		} catch (RuntimeException e) {
			log.error("HttpURLConnection", e);
		} catch (Exception e) {
			log.error("HttpURLConnection", e);
		} finally {
			if (con != null) {
				con.disconnect();
			}
		}
		StringBuffer buffer = new StringBuffer();
		BufferedReader br = null;
		try {
			if(con == null)
				throw new IOException("HttpURLConnection Exception");

			br = new BufferedReader(new InputStreamReader(
					con.getInputStream(), "UTF-8"));
			String temp;
			while ((temp = br.readLine()) != null) {
				buffer.append(temp);
			}
				
		} catch (RuntimeException e) {
			log.error("BufferedReader", e);
		} catch (Exception e) {
			log.error("BufferedReader", e);
		} finally {
			if (br != null) {
				try {
					br.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		return buffer.toString();
	}

	/**
	 * 取随机数
	 * 
	 * @param length
	 * @return
	 */
	private static String getRandomString(int length) {
		StringBuffer buffer = new StringBuffer(
				"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
		StringBuffer sb = new StringBuffer();
		Random random = new SecureRandom();
		int range = buffer.length();
		for (int i = 0; i < length; i++) {
			sb.append(buffer.charAt(random.nextInt(range)));
		}
		return sb.toString();
	}

	/**
	 * 将字节数组转换为十六进制字符串
	 * 
	 * @param byteArray
	 * @return
	 */
	private static String byteToStr(byte[] byteArray) {
		StringBuffer strDigest = new StringBuffer();
		for (int i = 0; i < byteArray.length; i++) {
			strDigest.append(byteToHexStr(byteArray[i]));
		}
		return strDigest.toString();
	}

	/**
	 * 将字节转换为十六进制字符串
	 * 
	 * @param mByte
	 * @return
	 */
	private static String byteToHexStr(byte mByte) {

		char[] Digit = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',
				'B', 'C', 'D', 'E', 'F' };
		char[] tempArr = new char[2];
		tempArr[0] = Digit[(mByte >>> 4) & 0X0F];
		tempArr[1] = Digit[mByte & 0X0F];

		String s = new String(tempArr);
		return s;
	}


	private static X509TrustManager xtm = new X509TrustManager() {

		public void checkClientTrusted(X509Certificate[] chain, String authType) {
		}

		public void checkServerTrusted(X509Certificate[] chain, String authType) {
		}

		public X509Certificate[] getAcceptedIssuers() {
			return null;
		}
	};

	private static HostnameVerifier hnv = new HostnameVerifier() {
		public boolean verify(String hostname, SSLSession session) {
			return true;
		}
	};

	private static void SSLInit() {

		SSLContext sslContext = null;
		try {
			sslContext = SSLContext.getInstance("TLS");
			X509TrustManager[] xtmArray = new X509TrustManager[] { xtm };
			sslContext.init(null, xtmArray, new java.security.SecureRandom());
		} catch (GeneralSecurityException gse) {
			if (log.isErrorEnabled())
				log.error(gse);
		}
		if (sslContext != null) {
			HttpsURLConnection.setDefaultSSLSocketFactory(sslContext
					.getSocketFactory());
		}
		HttpsURLConnection.setDefaultHostnameVerifier(hnv);
	}

	/**
	 * 
	 * 方法描述: 微信的appid 和 appsecret 是否已经设置
	 * 
	 * @return boolean
	 * @author lfg 2016年6月4日
	 */
	
	public static boolean isAppConfigSet() {
		if(appId == null || "".equals(appId) || appsecret == null || "".equals(appsecret))
			return false;
		return true;
	}
	
 
	public static String getAccess_token() {
		return access_token;
	} 
	
	public static void main(String[] args) throws  Exception {
		String appConfig = "wxfbbca0532240661b,89577de0bc20ae98d38046e622e14978";
		Map map = getSignature("http://www.baidu.com",appConfig);
		System.out.println(map);
		System.out.println(getAccess_token());
		
//		try {
//			if(WxTool.isAppConfigSet()){
//				resultMap = WxTool.getSignature(url);
//			}else{
//				
//				Map map = new HashMap<>();
//				map.put("ORG_CODE", MrtInfo.getOrgCode());
//				map.put("TENANT_ID", "00");
//				map.put("SHOP_ID", MrtInfo.getShopId());
//				map.put("DEFINE", "WX_APP_CONFIG");
//				//appid,appsecret
//				String appconfig = stockAnalysisMapper.getSysDefine(map);
//				//String appconfig = "wxfbbca0532240661b,89577de0bc20ae98d38046e622e14978";
//				resultMap = WxTool.getSignature(url,appconfig);
//			}
//			
//		} catch (Exception e) {
//			log.error("getSignature---Exception",e);
//			status = Code.ERROR_RUNTIME;
//		}
		
	}
}
