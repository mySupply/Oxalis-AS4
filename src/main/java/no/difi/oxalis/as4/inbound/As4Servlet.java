package no.difi.oxalis.as4.inbound;

import com.google.common.collect.Maps;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import no.difi.oxalis.api.settings.Settings;
import no.difi.oxalis.commons.security.KeyStoreConf;
import no.difi.vefa.peppol.security.api.CertificateValidator;
import org.apache.cxf.BusFactory;
import org.apache.cxf.jaxws.EndpointImpl;
import org.apache.cxf.transport.servlet.CXFNonSpringServlet;
import org.apache.cxf.ws.security.SecurityConstants;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.soap.MimeHeaders;
import javax.xml.ws.Endpoint;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.*;

@Singleton
public class As4Servlet extends CXFNonSpringServlet {

    @Inject
    private KeyStore keyStore;

    @Inject
    private Settings<KeyStoreConf> settings;

    @Inject
    private As4Provider provider;

    @Inject
    private CertificateValidator certificateValidator;

    @Override
    protected void loadBus(ServletConfig servletConfig) {
        super.loadBus(servletConfig);
        BusFactory.setDefaultBus(getBus());
        EndpointImpl endpointImpl = (EndpointImpl) Endpoint.publish("/", provider);

        Security.addProvider(new BouncyCastleProvider());
        Merlin encryptCrypto = new Merlin();
        encryptCrypto.setCryptoProvider(BouncyCastleProvider.PROVIDER_NAME);
        encryptCrypto.setKeyStore(keyStore);

        InputStream is = getClass().getResourceAsStream("/eutest_gateway_truststore.jks");
        KeyStore trust_store;

        try {
            trust_store = KeyStore.getInstance("jks");
            trust_store.load(is, "test123".toCharArray());

            encryptCrypto.setTrustStore(trust_store);
        }catch (Exception e){
            System.err.println("Unable to load TrustStore!");
        }

        // Properties
        Map<String, Object> inProps = Maps.newHashMap();
        inProps.put(WSHandlerConstants.ACTION, WSHandlerConstants.ENCRYPT+" "+WSHandlerConstants.SIGNATURE);
        String alias = settings.getString(KeyStoreConf.KEY_ALIAS);
        String password = settings.getString(KeyStoreConf.KEY_PASSWORD);
        PasswordCallbackHandler cb = new PasswordCallbackHandler(password);

        System.out.println("======== Crypto Info =======");

        System.out.println("Selected alias: " + alias);
        System.out.println("Selected password: " + password);

        System.out.println("KeyStore alias: ");
        try {
            Collections.list(encryptCrypto.getKeyStore().aliases()).forEach(s->{
                try {
                    System.out.println("- " + s.toString()+ " : " +  ((X509Certificate)encryptCrypto.getKeyStore().getCertificate(s)).getSubjectDN());
                } catch (KeyStoreException e) {
                    e.printStackTrace();
                }
            });
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        System.out.println("Truststore alias: ");
        try {
            Collections.list(encryptCrypto.getTrustStore().aliases()).forEach(s->{
                try {
                    System.out.print("- " + s.toString() + " : " +  ((X509Certificate)encryptCrypto.getTrustStore().getCertificate(s)).getSubjectDN());
                } catch (KeyStoreException e) {
                    e.printStackTrace();
                }
            });
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        System.out.println("Selected certificate:");
            CryptoType type = new CryptoType(CryptoType.TYPE.ALIAS);
            type.setAlias(alias);
        try {
            Arrays.asList(encryptCrypto.getX509Certificates(type)).forEach(s->System.out.println("- " + s.getSubjectDN()));
        } catch (WSSecurityException e) {
            e.printStackTrace();
        }


        inProps.put(WSHandlerConstants.PW_CALLBACK_REF, cb);
        inProps.put(WSHandlerConstants.ENCRYPTION_PARTS, "{}cid:Attachments");
        inProps.put(WSHandlerConstants.SIGNATURE_PARTS, "{}{}Body; {}cid:Attachments");
        inProps.put(WSHandlerConstants.SIG_KEY_ID, "DirectReference");
        inProps.put(WSHandlerConstants.USE_SINGLE_CERTIFICATE, "true");
        inProps.put(WSHandlerConstants.USE_REQ_SIG_CERT, "true");
        inProps.put(SecurityConstants.SIGNATURE_TOKEN_VALIDATOR, new CertificateValidatorSignatureTrustValidator(certificateValidator));

        OxalisAS4WsInInterceptor interceptor = new OxalisAS4WsInInterceptor(inProps, encryptCrypto, alias);
        org.apache.cxf.endpoint.Endpoint endpoint = endpointImpl.getServer().getEndpoint();
//        endpoint.getInInterceptors().add(new GZIPInInterceptor());
        endpoint.getInInterceptors().add(interceptor);
    }

    private MimeHeaders getHeaders(HttpServletRequest httpServletRequest) {
        Enumeration<?> enumeration = httpServletRequest.getHeaderNames();
        MimeHeaders headers = new MimeHeaders();
        while (enumeration.hasMoreElements()) {
            String headerName = (String) enumeration.nextElement();
            String headerValue = httpServletRequest.getHeader(headerName);
            StringTokenizer values = new StringTokenizer(headerValue, ",");
            while (values.hasMoreTokens()) {
                headers.addHeader(headerName, values.nextToken().trim());
            }
        }
        return headers;
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException {
        try {
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().write("Hello AS4 world\n");
        }catch ( IOException e ){
            throw new ServletException("Unable to send response", e);
        }
    }
}
