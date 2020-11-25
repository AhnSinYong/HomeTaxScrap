package com.homestaxt.scrap.controller;


import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.CookieHandler;
import java.net.CookieManager;
import java.net.HttpCookie;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;
//import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.DocumentHelper;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.jsoup.Connection;
import org.jsoup.Connection.Method;
import org.jsoup.Connection.Response;
import org.jsoup.Jsoup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

public class HomeTax {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private static final String pwd = "";
    private static final String priPath = "";
    private static final String certPath = "";

    /*
     * 홈택스 관련 추가 정보
     * NTS_REQUEST_SYSTEM_CODE_P : [TXPP]로그인시 / [TEET]전자세금계산서 / [TECR]현금영수증
     */

    public static void main(String args[]) throws Exception {
        HomeTax fm = new HomeTax();
        //fm.getTaxTypeFromNts("1112275759");

        HashMap<String, String> loginData = new HashMap<String, String>();
        loginData.put("signPriPath",priPath);
        loginData.put("signDerPath",certPath);
        loginData.put("signPassWord",pwd);

        HashMap<String, String> signData = fm.sign(loginData);
        fm.homeTaxLogin(signData);
        //System.out.println(fm.getCertificate(certPath).toString());

        System.out.println();
    }



    /**
     * 공인인증서를 사용하여 홈택스 로그인 시도 Method
     */
    public void homeTaxLogin(HashMap<String, String> param) throws Exception {

        logger.info("[ ************* homeTaxLogin param *************** ]");
        logger.info("cert : " + param.get("cert"));
        logger.info("logSgnt : " + param.get("logSgnt"));
        logger.info("randomEnc : " + param.get("randomEnc"));
        logger.info("pkcEncSsn : " + param.get("pkcEncSsn"));
        logger.info("TXPPsessionID : " + param.get("TXPPsessionID"));
        logger.info("WMONID : " + param.get("WMONID"));
        logger.info("NTS_LOGIN_SYSTEM_CODE_P : " + param.get("NTS_LOGIN_SYSTEM_CODE_P"));
        logger.info("[ ************************************************ ]");

        HashMap<String, String> cookies = new HashMap<String, String>();
        cookies.put("TXPPsessionID",param.get("TXPPsessionID"));
        cookies.put("WMONID",param.get("WMONID"));
        cookies.put("NTS_LOGIN_SYSTEM_CODE_P",param.get("NTS_LOGIN_SYSTEM_CODE_P"));

        Response res = Jsoup.connect("https://hometax.go.kr/pubcLogin.do?domain=hometax.go.kr&mainSys=Y")
                .data(param)
                .cookies(cookies)
                .timeout(6000)
                .method(Method.POST)
                .execute();

        logger.info("국세청 로그인 시도 결과 : " + res.body() );
        logger.info("국세청 로그인 COOKIE  : " + res.cookies() );

        // 공인인증서를 통해 로그인 성공시 TXPPsessionID 값이 새로 발급 된다.
        cookies.put("TXPPsessionID",res.cookies().get("TXPPsessionID"));

        if(res.body().contains("[ET") == false) {
            //taxScraping(cookies);
            //cashScraping(cookies);
            scraping(cookies , "TECR" , cookies);
        }

    }

    public void scraping(HashMap<String, String> cookies , String scrapType , HashMap<String, String> searchParam) throws Exception {

        /* 헤더 정보 */
        HashMap<String , String> headers = new HashMap<String, String>();
        headers.put("Content-Type", "application/xml; charset=UTF-8");

        /* 쿠키 정보 */
        cookies.put("NTS_LOGIN_SYSTEM_CODE_P", "TXPP" );
        cookies.put("NTS_REQUEST_SYSTEM_CODE_P", "TXPP" );
        cookies.put("nts_homtax:zoomVal", "100");
        cookies.put("nts_hometax:pkckeyboard", "none");
        cookies.put("nts_hometax:userId", "");
        cookies.put("NetFunnel_ID", "");

        Response res = null;

        res = Jsoup.connect("https://www.hometax.go.kr/permission.do?screenId=index_pp")
                .cookies(cookies)
                .requestBody("<map id='postParam'><popupYn>false</popupYn></map>")
                .timeout(6000)
                .method(Method.POST)
                .execute();

        Document document = DocumentHelper.parseText(res.body());

        // 나중에 데이터를 조회할때 필요한 값
        cookies.put("tin", document.valueOf("//map/tin"));

        String sessionUrl = "";

        if(scrapType.equals("TEET")) {
            // 전자세금계산서
            sessionUrl = "https://teet.hometax.go.kr/permission.do?screenId=UTEETBDA01";
        }else if(scrapType.equals("TECR")) {
            // 현금영수증
            sessionUrl = "https://tecr.hometax.go.kr/permission.do?screenId=UTECRCB001";
        }

        // 임시 SESSION ID 를 가져옴
        res = Jsoup.connect(sessionUrl)
                .headers(headers)
                .cookies(cookies)
                .requestBody("<map id='postParam'><popupYn>false</popupYn></map>")
                .timeout(6000)
                .method(Method.POST)
                .execute();

        logger.info("[ ************* 임시 SessionID GET 결과  ************* ]");
        logger.info("sessionID  : " + res.body());
        logger.info("sessionID COOKIES INFO : " + res.cookies());
        logger.info("[ ************************************************ ]");

        if(scrapType.equals("TEET")) {
            // 전자세금계산서
            cookies.put("TEETsessionID", res.cookies().get("TEETsessionID"));
        }else if(scrapType.equals("TECR")) {
            // 현금영수증
            cookies.put("TECRsessionID", res.cookies().get("TECRsessionID"));
        }

        // SESSION ID 를 얻어 SSO TOKEN 을 가져 옴
        String ssoToken = ssoTokenGet(cookies);

        String requestBodyStr = "<map id='postParam'>" + ssoToken + "<popupYn>false</popupYn></map>";

        res = Jsoup.connect(sessionUrl + "&domain=hometax.go.kr")
                .headers(headers)
                .cookies(cookies)
                .requestBody(requestBodyStr)
                .timeout(6000)
                .method(Method.POST)
                .execute();

        logger.info("[ ************* SessionID GET 결과 ************* ]");
        logger.info( res.body() );
        logger.info( "COOKIE INFO" + res.cookies() );
        logger.info("[ ****************************************** ]");

        // SSO TOKEN 을 이용하여 받은 SESSION ID 를 활용해야함
        // 정상 SESSION ID 를 가져오면 시스템 코드는 각 스크래핑 종류에 맞게 세팅해야함
        // 조회 조건 XML 형식의 문자열도 가져옴
        String requestBody = "";
        String scrapUrl = "";
        if(scrapType.equals("TEET")) {
            // 전자세금계산서
            cookies.put("TEETsessionID", res.cookies().get("TEETsessionID"));
            cookies.put("NTS_REQUEST_SYSTEM_CODE_P","TEET");
            requestBody = searchXmlGet(cookies, "TEET");
            // 스크랩핑해올 URL 정보도 세팅해둔다.
            scrapUrl = "https://teet.hometax.go.kr/wqAction.do?actionId=ATEETBDA001R01&screenId=UTEETBDA01&popupYn=false&realScreenId=";
        }else if(scrapType.equals("TECR")) {
            // 현금영수증
            cookies.put("TECRsessionID", res.cookies().get("TECRsessionID"));
            cookies.put("NTS_REQUEST_SYSTEM_CODE_P","TECR");
            requestBody = searchXmlGet(cookies, "TECR");
            // 스크랩핑해올 URL 정보도 세팅해둔다.
            scrapUrl = "https://tecr.hometax.go.kr/wqAction.do?actionId=ATECRCBA001R01&screenId=UTECRCB001&popupYn=false&realScreenId=";
        }

        String netFunnelId = netFunnelIdGet(cookies);
        cookies.put("NetFunnel_ID",netFunnelId);

        res = Jsoup.connect(scrapUrl)
                .cookies(cookies)
                .requestBody(requestBody)
                .headers(headers)
                .timeout(6000)
                .method(Method.POST)
                .ignoreContentType(true) // 컨텐츠 타입을 무시하고 가져오도록
                .execute();

        logger.info("[ ************* 드래곤볼 GET 결과 ************* ]");
        logger.info( res.body() );
        logger.info( "COOKIE INFO" + res.cookies() );
        logger.info("[ ****************************************** ]");

        // XML 로 받아온 데이터를 JSON 형식으로 변환
        org.json.JSONObject xmlJsonObject = org.json.XML.toJSONObject(res.body());

        xmlJsonObject = (org.json.JSONObject) xmlJsonObject.get("map");
        xmlJsonObject = (org.json.JSONObject) xmlJsonObject.get("list");

        org.json.JSONArray result = new org.json.JSONArray();

        if(!xmlJsonObject.isNull("map")) {
            logger.info( xmlJsonObject.get("map").getClass().getName() );
            result = (org.json.JSONArray) xmlJsonObject.get("map");
        }

        for(int i = 0; i < result.length(); i++) {
            System.out.println("[***********************************]");
            org.json.JSONObject item = (org.json.JSONObject) result.get(i);
            item.keySet().forEach(key -> System.out.println("key : " + key + "    value : " + item.get(key)));
        }

    }


    /*
     * 조회XML 양식 만들어주는 Method
     */
    public String searchXmlGet(HashMap<String, String> cookies , String scrapType) throws Exception{

        String requestBody = "";

        if(scrapType.equals("TEET")) {
            requestBody = "<map id=\"ATEETBDA001R01\">"
                    + " <icldLsatInfr>N</icldLsatInfr>"
                    + " <resnoSecYn>Y</resnoSecYn>"
                    + " <srtClCd>1</srtClCd>"
                    + " <srtOpt>01</srtOpt>"
                    + " <map id=\"pageInfoVO\">"
                    + " <pageSize>50</pageSize>" // 최대 50개까지 출력할수있음
                    + " <pageNum>1</pageNum>"
                    + " </map>"
                    + " <map id=\"excelPageInfoVO\" />"
                    + " <map id=\"etxivIsnBrkdTermDVOPrmt\">"
                    + " <tnmNm />"
                    + " <prhSlsClCd>02</prhSlsClCd>" // [01] 매출 / [02] 매입
                    + " <dtCl>01</dtCl>"
                    + " <bmanCd>01</bmanCd>"
                    + " <etxivClsfCd>all</etxivClsfCd>"
                    + " <isnTypeCd>all</isnTypeCd>"
                    + " <pageSize>10</pageSize>"
                    + " <splrTin></splrTin>" // 공급자
                    + " <dmnrTin>" + cookies.get("tin") + "</dmnrTin>" // 공급받는자
                    + " <cstnBmanTin></cstnBmanTin>"
                    + " <splrTxprDscmNo></splrTxprDscmNo>"
                    + " <dmnrTxprDscmNo></dmnrTxprDscmNo>"
                    + " <splrMpbNo></splrMpbNo>"
                    + " <dmnrMpbNo></dmnrMpbNo>"
                    + " <cstnBmanMpbNo></cstnBmanMpbNo>"
                    + " <etxivClCd>01</etxivClCd>"
                    + " <etxivKndCd>all</etxivKndCd>"
                    + " <splrTnmNm></splrTnmNm>"
                    + " <dmnrTnmNm></dmnrTnmNm>"
                    + " <inqrDtStrt>20201025</inqrDtStrt>"
                    + " <inqrDtEnd>20201123</inqrDtEnd> "
                    + " </map>"
                    + " </map>";
        }else if(scrapType.equals("TECR")) {
            requestBody = "<map id=\"ATECRCBA001R01\">\n"
                    +"<trsDtRngStrt>20201101</trsDtRngStrt>\n"
                    +"<trsDtRngEnd>20201122</trsDtRngEnd>\n"
                    +"<spjbTrsYn/><cshptUsgClCd/>\n"
                    +"<sumTotaTrsAmt/>\n"
                    +"<tin>" + cookies.get("tin") + "</tin>\n"
                    +"<totalCount>0</totalCount>\n"
                    +"<sumSplCft>22818</sumSplCft>\n"
                    +"<map id=\"pageInfoVO\">\n"
                    +"<pageSize>10</pageSize>\n"
                    +"<pageNum>1</pageNum>\n"
                    +"<totalCount>1</totalCount>\n"
                    +"</map>\n"
                    + "</map>" ;
        }

        return requestBody;
    }


    /*
     * netFunnelId 값을 가져오는 Method
     */
    public String netFunnelIdGet(HashMap<String, String> cookies) throws Exception{

        HashMap<String , String> data = new HashMap<>();

        data.put("opcode","5101");
        data.put("nfid","0");
        data.put("prefix","NetFunnel.gRtype=5101");
        data.put("sid","service_2");
        data.put("aid","ATECR_SEARCH");
        data.put("js","yes");

        Response res = Jsoup.connect("https://apct.hometax.go.kr/ts.wseq")
                .data(data)
                .cookies(cookies)
                .timeout(6000)
                .method(Method.GET)
                .ignoreContentType(true) // 컨텐츠 타입을 무시하고 가져오도록
                .execute();

        logger.info("[ ************* NetFunnel GET 결과 ************* ]");
        logger.info( res.body() );
        logger.info( "COOKIE INFO" + res.cookies() );
        logger.info("[ ****************************************** ]");

        String netFunnelDecoder = res.body();

        // NetFunnel_ID값만 얻기 위해 공백으로 치환
        String netFunnel = netFunnelDecoder.replace("NetFunnel.gRtype=5101NetFunnel.gControl.result='", "").replace("'; NetFunnel.gControl._showResult();", "");

        return netFunnel;
    }

    /*
     * SSO TOKEN URL 주소 만들어주기
     * */
    public String ssoTokenGet(HashMap<String, String> cookies) throws Exception{

        String today = new SimpleDateFormat("yyyy_MM_dd").format(new Date());
        String seed = "qwertyuiopasdfghjklzxxcvbnm0123456789QWERTYUIOPASDDFGHJKLZXCVBNBM";
        String randomString = "";
        for (int i = 0; i < 20; i++) {
            Double d = Math.floor(Math.random() * seed.length());
            randomString += seed.charAt(d.intValue());
        }

        String ssoTokenUrl = "https://hometax.go.kr/token.do?query=" + "_" + randomString + "&postfix=" + today;

        logger.info("[ ************* token.do param ************* ]");
        logger.info("SSO TOKEN URL : " + ssoTokenUrl );
        logger.info("WMONID : " + cookies.get("WMONID"));
        logger.info("TXPPsessionID : " + cookies.get("TXPPsessionID"));
        logger.info("TEETsessionID : " + cookies.get("TEETsessionID"));
        logger.info("NetFunnel_ID : " + cookies.get("NetFunnel_ID"));
        logger.info("NTS_REQUEST_SYSTEM_CODE_P : " + cookies.get("NTS_REQUEST_SYSTEM_CODE_P"));
        logger.info("NTS_LOGIN_SYSTEM_CODE_P : " + cookies.get("NTS_LOGIN_SYSTEM_CODE_P"));
        logger.info("nts_homtax:zoomVal : " + cookies.get("nts_homtax:zoomVal"));
        logger.info("nts_hometax:pkckeyboard : " + cookies.get("nts_hometax:pkckeyboard"));
        logger.info("[ ****************************************** ]");

        Response res = Jsoup.connect(ssoTokenUrl)
                .cookies(cookies)
                .timeout(6000)
                .method(Method.GET)
                .execute();

        String ssoTokenDecoder = res.body();

        // 콜백 함수명 지우고 토큰값만 얻기 위해 공백으로 치환
        String ssoToken = ssoTokenDecoder.replace("nts_reqPortalCallback(\"", "").replace("\");", "");

        return ssoToken;
    }

    public PrivateKey getPrivateKey(byte[] decryptedKey) throws Exception {
        // 복호화된 내용을 PrivateKey 객체로 변환
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(decryptedKey);
        KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
        logger.info(kf.generatePrivate(ks).toString());
        return kf.generatePrivate(ks);
    }

    public byte[] getDecryptedKey(String filePath , String passWord) throws Exception {

        byte[] decryptedKey = null;
        byte[] encodedKey = FileUtils.readFileToByteArray(new File(filePath));
        org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = null;

        try (ByteArrayInputStream bIn = new ByteArrayInputStream(encodedKey); ASN1InputStream aIn = new ASN1InputStream(bIn);)
        {
            ASN1Sequence asn1Sequence = (ASN1Sequence) aIn.readObject();
            AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(asn1Sequence.getObjectAt(0));
            ASN1OctetString data = ASN1OctetString.getInstance(asn1Sequence.getObjectAt(1));
            encryptedPrivateKeyInfo = new org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo(algId, data.getEncoded());
            String privateKeyAlgName = encryptedPrivateKeyInfo.getEncryptionAlgorithm().getAlgorithm().getId();
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            //logger.info("암호화 방식 : " + privateKeyAlgName);
            if ("1.2.840.113549.1.5.13".equals(privateKeyAlgName)) {
                // PKCS5PBES2
                // 개인키 암호화 정보에서 Salt, Iteration Count(IC), Initial Vector(IV)를 가져오는 로직
                ASN1Sequence asn1Sequence2 = (ASN1Sequence)algId.getParameters();
                ASN1Sequence asn1Sequence3 = (ASN1Sequence)asn1Sequence2.getObjectAt(0);

                // PBKDF2 Key derivation algorithm
                ASN1Sequence asn1Sequence33 = (ASN1Sequence)asn1Sequence3.getObjectAt(1);

                // Salt 값
                DEROctetString derOctetStringSalt = (DEROctetString)asn1Sequence33.getObjectAt(0);

                // Iteration Count(IC)
                ASN1Integer asn1IntegerIC = (ASN1Integer)asn1Sequence33.getObjectAt(1);
                ASN1Sequence asn1Sequence4 = (ASN1Sequence)asn1Sequence2.getObjectAt(1);

                // Initial Vector(IV)
                DEROctetString derOctetStringIV = (DEROctetString)asn1Sequence4.getObjectAt(1);

                // 복호화 키 생성
                int keySize = 256;
                PBEParametersGenerator generator = new PKCS5S2ParametersGenerator();
                generator.init( PBEParametersGenerator.PKCS5PasswordToBytes(passWord.toCharArray()), derOctetStringSalt.getOctets(), asn1IntegerIC.getValue().intValue());
                byte[] iv = derOctetStringIV.getOctets(); KeyParameter key = (KeyParameter)generator.generateDerivedParameters(keySize);

                // 복호화 수행
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                SecretKeySpec secKey = new SecretKeySpec(key.getKey(), "SEED");
                Cipher cipher = Cipher.getInstance("SEED/CBC/PKCS5Padding", "BC");
                cipher.init(Cipher.DECRYPT_MODE, secKey, ivSpec);
                decryptedKey = cipher.doFinal(data.getOctets());
            } else {
                // 1.2.410.200004.1.15 seedCBCWithSHA1
                ASN1Sequence asn1Sequence2 = (ASN1Sequence)algId.getParameters();
                // Salt 값
                DEROctetString derOctetStringSalt = (DEROctetString)asn1Sequence2.getObjectAt(0);
                // Iteration Count(IC)
                ASN1Integer asn1IntegerIC = (ASN1Integer)asn1Sequence2.getObjectAt(1);

                // 복호화 키 생성
                byte[] dk = new byte[20];
                MessageDigest md = MessageDigest.getInstance("SHA1");
                md.update(passWord.getBytes());
                md.update(derOctetStringSalt.getOctets());
                dk = md.digest();
                for (int i = 1; i < asn1IntegerIC.getValue().intValue(); i++) {
                    dk = md.digest(dk);
                }
                byte[] keyData = new byte[16];
                System.arraycopy(dk, 0, keyData, 0, 16);
                byte[] digestBytes = new byte[4];
                System.arraycopy(dk, 16, digestBytes, 0, 4);
                MessageDigest digest = MessageDigest.getInstance("SHA-1");
                digest.reset(); digest.update(digestBytes);
                byte[] div = digest.digest();

                // Initial Vector(IV) 생성
                byte[] iv = new byte[16];
                System.arraycopy(div, 0, iv, 0, 16);
                if ("1.2.410.200004.1.4".equals(privateKeyAlgName)) {
                    iv = "012345678912345".getBytes();
                }

                // 복호화 수행
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                SecretKeySpec secKey = new SecretKeySpec(keyData, "SEED");
                Cipher cipher = Cipher.getInstance("SEED/CBC/PKCS5Padding", "BC");
                cipher.init(Cipher.DECRYPT_MODE, secKey, ivSpec);
                decryptedKey = cipher.doFinal(data.getOctets());
            }

        }
        return decryptedKey;

    }

    /*
     * 공인인증서 개인키에서 신원확인 값 추출 Method
     * Random Value
     */
    public String getIdentityCheck(String filePath, String passWord) throws Exception{

        if (null == passWord || "".equals(passWord)) {
            return null;
        }
        try {
            byte[] decryptedKey = getDecryptedKey(filePath, passWord);
            try (ByteArrayInputStream bIn2 = new ByteArrayInputStream(decryptedKey); ASN1InputStream aIn2 = new ASN1InputStream(bIn2);) {

                ASN1Object asn1Object = (ASN1Object) aIn2.readObject();
                DERSequence seq = (DERSequence) asn1Object.toASN1Object();
                //logger.info("DLSequence seq size : " +  seq.size());

                int i = 0;
                while (i < seq.size()) {
                    //logger.info("CLASS NAME : " +  seq.getObjectAt(i).getClass().getName());
                    if (seq.getObjectAt(i) instanceof DERTaggedObject) {
                        DERTaggedObject dertTaggedObject = (DERTaggedObject) seq.getObjectAt(i);
                        if (dertTaggedObject.getTagNo() == 0) {
                            DERSequence seq2 = (DERSequence) dertTaggedObject.getObject();
                            //logger.info("seq2 : " +  seq2.toString());
                            int j = 0;
                            while (j < seq2.size()) {
                                //logger.info("seq2.getObjectAt(i)" +  seq2.getObjectAt(j).getClass().getName());
                                if (seq2.getObjectAt(j) instanceof ASN1ObjectIdentifier) {
                                    ASN1ObjectIdentifier idRandomNumOID = (ASN1ObjectIdentifier) seq2.getObjectAt(j);
                                    //logger.info("idRandomNumOID : " +  idRandomNumOID.toString());
                                    if ("1.2.410.200004.10.1.1.3".equals(idRandomNumOID.toString())) {
                                        DERSet derSet = (DERSet) seq2.getObjectAt(j + 1);
                                        DERBitString DERBitString = (DERBitString) derSet.getObjectAt(0);
                                        //logger.info("DERBitString : " +  DERBitString);
                                        DEROctetString DEROctetString = new DEROctetString(DERBitString.getBytes());
                                        return Base64.getEncoder().encodeToString(DEROctetString.getOctets());
                                    }
                                }
                                j++;
                            }
                        }
                    }
                    i++;
                }
            }
        } catch (Exception e) {
            logger.error("getIdentityCheck 오류 : ", e);
        }
        return null;
    }

    public X509Certificate getCertificate(String certPath) throws Exception {
        FileInputStream fis = null;
        X509Certificate X509certificate = null;
        try {
            fis = new FileInputStream(certPath);
            X509certificate = (X509Certificate) CertificateFactory.getInstance("X509").generateCertificate(fis);
        } catch (Exception e) {
            logger.error(e.getMessage());
        } finally {
            try {
                if (fis != null) {
                    fis.close();
                }
            } catch (IOException e) {
                logger.error(e.getMessage());
            }
        }
        return X509certificate;
    }

    /**
     * 전자서명 Method
     * @return byte[]
     * @throws Exception
     */
    public HashMap<String, String> sign(HashMap<String, String> loginData) throws Exception {

        String signPriPath = loginData.get("signPriPath");
        String signDerPath = loginData.get("signDerPath");
        String signPassWord = loginData.get("signPassWord");

        byte[] privateKeyByte = getDecryptedKey(signPriPath, signPassWord);
        X509Certificate certificate = getCertificate(signDerPath);
        Date date = new Date();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
        String toDay = sdf.format(date);

        // 개인키
        PrivateKey privateKey = getPrivateKey(privateKeyByte);

        // 공개키
        PublicKey publicKey = certificate.getPublicKey();

        // 개인키 신원확인 키 값
        String privateRandomValue = getIdentityCheck(signPriPath, signPassWord);

        // 서명용 문자열과 쿠키 정보들을 가져옴
        JSONObject signTextInfo = getSignText();

        String msg = signTextInfo.get("pkcEncSsn").toString();

        Signature signaturePrivate = Signature.getInstance("SHA256withRSA");//SHA256withRSA

        signaturePrivate.initSign(privateKey);

        signaturePrivate.update(msg.getBytes());

        byte[] sign = signaturePrivate.sign();

        String msgB = msg;

        Signature signaturePublic = Signature.getInstance("SHA256withRSA");

        signaturePublic.initVerify(publicKey);

        signaturePublic.update(msgB.getBytes());

        boolean verifty = signaturePublic.verify(sign);

        logger.info("전자서명 검증 결과 : " + verifty);

        logger.info("[ ******************************************************************* ]");
        logger.info("서명용 공개키 일렬번호 : " + certificate.getSerialNumber());
        logger.info("전자서명한 값 : " +  Base64.getEncoder().encodeToString(sign) );
        logger.info("서명용 공개키 BASE 64 PEM : " + "-----BEGIN CERTIFICATE-----" + Base64.getEncoder().encodeToString(certificate.getEncoded()) + "-----END CERTIFICATE-----" );
        logger.info("서명용 개인키 RANDOM 값 : " + privateRandomValue);
        logger.info("[ ******************************************************************* ]");

        String certPem = "-----BEGIN CERTIFICATE-----" + Base64.getEncoder().encodeToString(certificate.getEncoded()) + "-----END CERTIFICATE-----";
        String logSgnt = signTextInfo.get("pkcEncSsn").toString() + "$" + certificate.getSerialNumber() + "$" + toDay + "$" + Base64.getEncoder().encodeToString(sign) ;
        logSgnt = Base64.getEncoder().encodeToString( logSgnt.getBytes() );
        HashMap<String, String> param = new HashMap<String, String>();


        param.put("cert", certPem);
        param.put("logSgnt", logSgnt); //서명으로 사용할 문자열 + $ + 서명용공개키 인증서 일렬번호 + $ + yyyyMMddHHmmss + $ + 전자서명한 값
        param.put("pkcLgnClCd", "04");
        param.put("pkcLoginYnImpv", "Y");
        param.put("randomEnc",privateRandomValue);
        param.put("pkcEncSsn",signTextInfo.get("pkcEncSsn").toString());
        param.put("WMONID",signTextInfo.get("WMONID").toString());
        param.put("TXPPsessionID",signTextInfo.get("TXPPsessionID").toString());
        param.put("NTS_LOGIN_SYSTEM_CODE_P", "TXPP");

        return param;
    }

    /**
     * 서명용 문자열 가져오는 Method
     * @return
     * @throws Exception
     */
    public JSONObject getSignText() throws Exception {

        CookieManager cookieManager = new CookieManager();
        CookieHandler.setDefault(cookieManager);
        HttpURLConnection conn = null;

        URL url = new URL("https://www.hometax.go.kr/wqAction.do?actionId=ATXPPZXA001R01&screenId=UTXPPABA01");
        conn = (HttpURLConnection) url.openConnection();
        //conn.getContent();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(conn.getOutputStream()));

        bw.flush();
        bw.close();

        int responseCode = conn.getResponseCode();
        if (responseCode == 400) {
            System.out.println("400 - ERROR");
        } else if (responseCode == 401) {
            System.out.println("401 - ERROR");
        } else if (responseCode == 500) {
            System.out.println("500 - ERROR");
        } else {

            BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line = "";
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
            JSONParser parser = new JSONParser();
            JSONObject result = (JSONObject) parser.parse(sb.toString());

            //logger.info("Response 결과 : "+conn.getHeaderFields());

            List<HttpCookie> cookies = cookieManager.getCookieStore().getCookies();
            for (HttpCookie cookie : cookies) {
                result.put(cookie.getName(), cookie.getValue());
            }

            logger.info("[ ************* 서명 문자열 GET 결과 ************* ]");
            logger.info( "WMONID : " + result.get("WMONID") );
            logger.info( "TXPPsessionID : " + result.get("TXPPsessionID") );
            logger.info( "pkcEncSsn : " + result.get("pkcEncSsn") );
            logger.info("[ ****************************************** ]");

            return result;
        }
        return null;
    }






    /*
     * 휴폐업 / 과세유형 사업자 검색 Method
     * */
    public void getTaxTypeFromNts(String businessRegNo) {

        if (null == businessRegNo || "".equals(businessRegNo)) {
            throw new RuntimeException("조회할 사업자등록번호를 입력해주세요.");
        }

        String txprDscmNo = StringUtils.replace(businessRegNo, "-", "");

        if (txprDscmNo.length() != 10) {
            throw new RuntimeException("조회할 사업자등록번호를 올바로 입력해주세요.");
        }

        String dongCode = txprDscmNo.substring(3, 5);
        String url = "https://teht.hometax.go.kr/wqAction.do?actionId=ATTABZAA001R08&screenId=UTEABAAA13&popupYn=false&realScreenId=";
        Map<String, String> headers = new HashMap<>();
        headers.put("Accept", "application/xml; charset=UTF-8");
        headers.put("Accept-Encoding", "gzip, deflate, br");
        headers.put("Accept-Language", "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7");
        headers.put("Connection", "keep-alive");
        headers.put("Content-Length", "257");
        headers.put("Content-Type", "application/xml; charset=UTF-8");
        headers.put("Host", "teht.hometax.go.kr");
        headers.put("Origin", "https://teht.hometax.go.kr");
        headers.put("Referer", "https://teht.hometax.go.kr/websquare/websquare.html?w2xPath=/ui/ab/a/a/UTEABAAA13.xml");
        headers.put("Sec-Fetch-Mode", "cors");
        headers.put("Sec-Fetch-Site", "same-origin");
        headers.put("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36");
        final String CRLF = "\n";
        StringBuffer sb = new StringBuffer();
        sb.append("<map id=\"ATTABZAA001R08\">" + CRLF);
        sb.append(" <pubcUserNo/>" + CRLF);
        sb.append(" <mobYn>N</mobYn>" + CRLF);
        sb.append(" <inqrTrgtClCd>1</inqrTrgtClCd>" + CRLF);
        sb.append(" <txprDscmNo>" + txprDscmNo + "</txprDscmNo>" + CRLF);
        sb.append(" <dongCode>" + dongCode + "</dongCode>" + CRLF);
        sb.append(" <psbSearch>Y</psbSearch>" + CRLF);
        sb.append(" <map id=\"userReqInfoVO\"/>" + CRLF);
        sb.append("</map>" + CRLF);
        String body = sb.toString();

        Map<String, String> map = new HashMap<>();

        try {

            Response res = Jsoup.connect(url).headers(headers).requestBody(body).timeout(3000).method(Method.POST).execute();

            if (logger.isDebugEnabled()) {
                logger.debug(res.body());
            }

            Document document = DocumentHelper.parseText(res.body());

            document.valueOf("//map/trtCntn");

            String trtCntn = nvl(document.valueOf("//map/trtCntn"));

            if (logger.isDebugEnabled()) {
                logger.debug("trtCntn[" + trtCntn + "]");
            }

            map.put(businessRegNo, trtCntn);

        } catch (IOException e) {
            logger.error("Jsoup 오류", e);
        } catch (DocumentException e) {
            logger.error("Document parse 오류", e);
        }

        for (String mapkey : map.keySet()){
            logger.info("[ key : "+mapkey+"     value : "+map.get(mapkey) + " ]");
        }

    }

    public String nvl(String param) {
        if(param == null) {
            param = "";
        }
        return param;
    }
}
