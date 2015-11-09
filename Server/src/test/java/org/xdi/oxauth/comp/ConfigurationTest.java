/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.comp;

import java.io.File;
import java.io.FileInputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.io.IOUtils;
import org.testng.Assert;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;
import org.xdi.oxauth.BaseComponentTestAdapter;
import org.xdi.oxauth.model.config.Conf;
import org.xdi.oxauth.model.config.Configuration;
import org.xdi.oxauth.model.config.ConfigurationFactory;
import org.xdi.oxauth.model.util.Util;
import org.xdi.oxauth.util.ServerUtil;

/**
 * @author Yuriy Zabrovarnyy
 * @version 0.9, 03/01/2013
 */

public class ConfigurationTest extends BaseComponentTestAdapter {

    /*
    Configuration must be present, otherwise server will not start normally... There is fallback configuration from
    file but server will not work as expected in cluster.`
     */
    @Test
    public void configurationPresence() {
        final String dn = ConfigurationFactory.instance().getLdapConfiguration().getString("configurationEntryDN");
        final Conf conf = getLdapManager().find(Conf.class, dn);
        Assert.assertTrue(conf != null && Util.allNotBlank(conf.getDynamic(), conf.getErrors(), conf.getStatics(), conf.getWebKeys()));
    }

    /*
    Useful test method to get create newest test configuration. It shouldn't be used directly for testing.
     */
//    @Test
    public void createLatestTestConfInLdapFromFiles() throws Exception {
        final String prefix = "U:\\own\\project\\oxAuth\\Server\\src\\test\\resources\\conf";

        final String errorsFile = prefix + "\\oxauth-errors.json";
        final String staticFile = prefix + "\\oxauth-static-conf.json";
        final String webKeysFile = prefix + "\\oxauth-web-keys.json";
        final String configFile = prefix + "\\oxauth-config.xml";

        final String errorsJson = IOUtils.toString(new FileInputStream(errorsFile));
        final String staticConfJson = IOUtils.toString(new FileInputStream(staticFile));
        final String webKeysJson = IOUtils.toString(new FileInputStream(webKeysFile));
        final String configJson = ServerUtil.createJsonMapper().writeValueAsString(loadConfFromFile(configFile));

        final Conf c = new Conf();
        c.setDn("ou=testconfiguration,o=@!1111,o=gluu");
        c.setDynamic(configJson);
        c.setErrors(errorsJson);
        c.setStatics(staticConfJson);
        c.setWebKeys(webKeysJson);
        getLdapManager().persist(c);
    }

    private static Configuration loadConfFromFile(String p_filePath) throws JAXBException {
        final JAXBContext jc = JAXBContext.newInstance(Configuration.class);
        final Unmarshaller u = jc.createUnmarshaller();
        return (Configuration) u.unmarshal(new File(p_filePath));
    }
}
