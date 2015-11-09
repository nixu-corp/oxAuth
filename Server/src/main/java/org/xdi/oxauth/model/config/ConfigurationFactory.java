/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package org.xdi.oxauth.model.config;

import java.io.File;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.lang.StringUtils;
import org.gluu.site.ldap.persistence.LdapEntryManager;
import org.gluu.site.ldap.persistence.exception.LdapMappingException;
import org.jboss.seam.Component;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.AutoCreate;
import org.jboss.seam.annotations.Create;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Observer;
import org.jboss.seam.annotations.Scope;
import org.jboss.seam.annotations.Startup;
import org.jboss.seam.annotations.async.Asynchronous;
import org.jboss.seam.async.TimerSchedule;
import org.jboss.seam.contexts.Contexts;
import org.jboss.seam.contexts.Lifecycle;
import org.jboss.seam.core.Events;
import org.jboss.seam.log.Log;
import org.jboss.seam.log.Logging;
import org.xdi.exception.ConfigurationException;
import org.xdi.oxauth.model.error.ErrorMessages;
import org.xdi.oxauth.model.error.ErrorResponseFactory;
import org.xdi.oxauth.model.jwk.JSONWebKeySet;
import org.xdi.oxauth.util.ServerUtil;
import org.xdi.util.properties.FileConfiguration;

/**
 * @author Yuriy Zabrovarnyy
 * @author Javier Rojas Blum
 * @author Yuriy Movchan
 * @version 0.9 February 12, 2015
 */
@Scope(ScopeType.APPLICATION)
@Name("configurationFactory")
@AutoCreate
@Startup
public class ConfigurationFactory {

    private static final Log LOG = Logging.getLog(ConfigurationFactory.class);

    public final static String LDAP_CONFIGUARION_RELOAD_EVENT_TYPE = "LDAP_CONFIGUARION_RELOAD";
    private final static String EVENT_TYPE = "ConfigurationFactoryTimerEvent";
    private final static int DEFAULT_INTERVAL = 30; // 30 seconds

    static {
        if ((System.getProperty("catalina.base") != null) && (System.getProperty("catalina.base.ignore") == null)) {
            BASE_DIR = System.getProperty("catalina.base");
        } else if (System.getProperty("catalina.home") != null) {
            BASE_DIR = System.getProperty("catalina.home");
        } else if (System.getProperty("jboss.home.dir") != null) {
            BASE_DIR = System.getProperty("jboss.home.dir");
        } else {
            BASE_DIR = null;
        }
    }

    private static final String BASE_DIR;
    private static final String DIR = BASE_DIR + File.separator + "conf" + File.separator;

    private static final String CONFIG_RELOAD_MARKER_FILE_PATH = DIR + "oxauth.config.reload";

    private static final String LDAP_FILE_PATH = DIR + "oxauth-ldap.properties";

    @Logger
    private Log log;

    private final String CONFIG_FILE_NAME = "oxauth-config.xml";
    private final String ERRORS_FILE_NAME = "oxauth-errors.json";
    private final String STATIC_CONF_FILE_NAME = "oxauth-static-conf.json";
    private final String WEB_KEYS_FILE_NAME = "oxauth-web-keys.json";
    private final String SALT_FILE_NAME = "salt";

    private String confDir, configFilePath, errorsFilePath, staticConfFilePath, webKeysFilePath, saltFilePath;

    private FileConfiguration ldapConfiguration;
    private Configuration m_conf;
    private StaticConf m_staticConf;
    private JSONWebKeySet m_jwks;

    private AtomicBoolean isActive;

    private long ldapFileLastModifiedTime = -1;
    private long confFileLastModifiedTime = -1;
    private long errorsFileLastModifiedTime = -1;
    private long staticConfFileLastModifiedTime = -1;
    private long webKeysFileLastModifiedTime = -1;

    @Create
    public void init() {
    	loadLdapConfiguration();
    	this.confDir = confDir();

    	this.configFilePath = confDir + CONFIG_FILE_NAME;
    	this.errorsFilePath = confDir + ERRORS_FILE_NAME;
    	this.staticConfFilePath = confDir + STATIC_CONF_FILE_NAME;
    	this.webKeysFilePath = getLdapConfiguration().getString("certsDir") + File.separator + WEB_KEYS_FILE_NAME;
    	this.saltFilePath = confDir + SALT_FILE_NAME;
    }

    @Observer("org.jboss.seam.postInitialization")
    public void initReloadTimer() {
        this.isActive = new AtomicBoolean(false);

        final long delayBeforeFirstRun = 60 * 1000L;
        Events.instance().raiseTimedEvent(EVENT_TYPE, new TimerSchedule(delayBeforeFirstRun, DEFAULT_INTERVAL * 1000L));
    }

    @Observer(EVENT_TYPE)
    @Asynchronous
    public void reloadConfigurationTimerEvent() {
        if (this.isActive.get()) {
            return;
        }

        if (!this.isActive.compareAndSet(false, true)) {
            return;
        }

        try {
            reloadConfiguration();
        } catch (Throwable ex) {
            log.error("Exception happened while reloading application configuration", ex);
        } finally {
            this.isActive.set(false);
        }
    }

    private void reloadConfiguration() {
        File reloadMarker = new File(CONFIG_RELOAD_MARKER_FILE_PATH);

        if (reloadMarker.exists()) {
            boolean isAnyChanged = false;

            File ldapFile = new File(LDAP_FILE_PATH);
            File configFile = new File(configFilePath);
            File errorsFile = new File(errorsFilePath);
            File staticConfFile = new File(staticConfFilePath);
            File webkeysFile = new File(webKeysFilePath);

            if (configFile.exists()) {
                final long lastModified = configFile.lastModified();
                if (lastModified > confFileLastModifiedTime) { // reload configuration only if it was modified
                    reloadConfFromFile();
                    confFileLastModifiedTime = lastModified;
                    isAnyChanged = true;
                }
            }

            if (errorsFile.exists()) {
                final long lastModified = errorsFile.lastModified();
                if (lastModified > errorsFileLastModifiedTime) { // reload configuration only if it was modified
                    reloadErrorsFromFile();
                    errorsFileLastModifiedTime = lastModified;
                    isAnyChanged = true;
                }
            }

            if (staticConfFile.exists()) {
                final long lastModified = staticConfFile.lastModified();
                if (lastModified > staticConfFileLastModifiedTime) { // reload configuration only if it was modified
                    reloadStaticConfFromFile();
                    staticConfFileLastModifiedTime = lastModified;
                    isAnyChanged = true;
                }
            }

            if (webkeysFile.exists()) {
                final long lastModified = webkeysFile.lastModified();
                if (lastModified > webKeysFileLastModifiedTime) { // reload configuration only if it was modified
                    reloadWebkeyFromFile();
                    webKeysFileLastModifiedTime = lastModified;
                    isAnyChanged = true;
                }
            }

            if (isAnyChanged) {
                persistToLdap(ServerUtil.getLdapManager());
            }

            // Reload LDAP configuration after persisting configuration updates
            if (ldapFile.exists()) {
                final long lastModified = ldapFile.lastModified();
                if (lastModified > ldapFileLastModifiedTime) { // reload configuration only if it was modified
                    loadLdapConfiguration();
                    ldapFileLastModifiedTime = lastModified;
                    Events.instance().raiseAsynchronousEvent(LDAP_CONFIGUARION_RELOAD_EVENT_TYPE);
                    isAnyChanged = true;
                }
            }

        }
    }

    private void determineConfigurationLastModificationTime() {
		File ldapFile = new File(LDAP_FILE_PATH);
		File configFile = new File(configFilePath);
		File errorsFile = new File(errorsFilePath);
		File staticConfFile = new File(staticConfFilePath);
		File webKeysFile = new File(webKeysFilePath);

		if (ldapFile.exists()) {
			this.ldapFileLastModifiedTime = ldapFile.lastModified();
		}

		if (configFile.exists()) {
			this.confFileLastModifiedTime = configFile.lastModified();
		}

		if (errorsFile.exists()) {
			this.errorsFileLastModifiedTime = errorsFile.lastModified();
		}

		if (staticConfFile.exists()) {
			this.staticConfFileLastModifiedTime = staticConfFile.lastModified();
		}

		if (webKeysFile.exists()) {
			this.webKeysFileLastModifiedTime = webKeysFile.lastModified();
		}
    }

    private String confDir() {
        final String confDir = getLdapConfiguration().getString("confDir");
        if (StringUtils.isNotBlank(confDir)) {
            return confDir;
        }

        return DIR;
    }

    public FileConfiguration getLdapConfiguration() {
        return ldapConfiguration;
    }

    public Configuration getConfiguration() {
        return m_conf;
    }

    public StaticConf getStaticConfiguration() {
        return m_staticConf;
    }

    public BaseDnConfiguration getBaseDn() {
        return getStaticConfiguration().getBaseDn();
    }

    public JSONWebKeySet getWebKeys() {
        return m_jwks;
    }

    public void create() {
        if (!createFromLdap(true)) {
            LOG.error("Failed to load configuration from LDAP. Please fix it!!!.");
            throw new ConfigurationException("Failed to load configuration from LDAP.");
//            LOG.warn("Emergency configuration load from files.");
//            createFromFile();
        } else {
            LOG.info("Configuration loaded successfully.");
        }
    	determineConfigurationLastModificationTime();
    }

    private void createFromFile() {
        reloadConfFromFile();
        reloadErrorsFromFile();
        reloadStaticConfFromFile();
        reloadWebkeyFromFile();
    }

    private void reloadWebkeyFromFile() {
        final JSONWebKeySet webKeysFromFile = loadWebKeysFromFile();
        if (webKeysFromFile != null) {
            LOG.info("Reloaded web keys from file: " + webKeysFilePath);
            m_jwks = webKeysFromFile;
        } else {
            LOG.error("Failed to load web keys configuration from file: " + webKeysFilePath);
        }
    }

    private void reloadStaticConfFromFile() {
        final StaticConf staticConfFromFile = loadStaticConfFromFile();
        if (staticConfFromFile != null) {
            LOG.info("Reloaded static conf from file: " + staticConfFilePath);
            m_staticConf = staticConfFromFile;
        } else {
            LOG.error("Failed to load static configuration from file: " + staticConfFilePath);
        }
    }

    private void reloadErrorsFromFile() {
        final ErrorMessages errorsFromFile = loadErrorsFromFile();
        if (errorsFromFile != null) {
            LOG.info("Reloaded errors from file: " + errorsFilePath);
            final ErrorResponseFactory f = ServerUtil.instance(ErrorResponseFactory.class);
            f.setMessages(errorsFromFile);
        } else {
            LOG.error("Failed to load errors from file: " + errorsFilePath);
        }
    }

    private void reloadConfFromFile() {
        final Configuration configFromFile = loadConfFromFile();
        if (configFromFile != null) {
            LOG.info("Reloaded configuration from file: " + configFilePath);
            m_conf = configFromFile;
        } else {
            LOG.error("Failed to load configuration from file: " + configFilePath);
        }
    }

    public boolean updateFromLdap() {
        return createFromLdap(false);
    }

    private boolean createFromLdap(boolean p_recoverFromFiles) {
        LOG.info("Loading configuration from LDAP...");
        final LdapEntryManager ldapManager = ServerUtil.getLdapManager();
        final String dn = getLdapConfiguration().getString("configurationEntryDN");
        try {
            final Conf conf = ldapManager.find(Conf.class, dn);
            if (conf != null) {
                init(conf);
                return true;
            }
        } catch (LdapMappingException e) {
            LOG.warn(e.getMessage());
            if (p_recoverFromFiles) {
                LOG.info("Unable to find configuration in LDAP, try to create configuration entry in LDAP... ");
                if (getLdapConfiguration().getBoolean("createLdapConfigurationEntryIfNotExist")) {
                    if (reloadFromFileAndPersistToLdap(ldapManager)) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        }

        return false;
    }

    private boolean reloadFromFileAndPersistToLdap(LdapEntryManager ldapManager) {
        createFromFile();
        return persistToLdap(ldapManager);
    }

    private boolean persistToLdap(LdapEntryManager ldapManager) {
        final Conf conf = asConf();
        if (conf != null) {
            try {
                ldapManager.persist(conf);
                LOG.info("Configuration entry is created in LDAP.");
                return true;
            } catch (Exception ex) {

                try {
                    ldapManager.merge(conf);
                    LOG.info("Configuration entry updated in LDAP.");
                    return true;
                } catch (Exception e) {
                    LOG.error(ex.getMessage(), ex);
                    LOG.error(e.getMessage(), e);
                }
            }
        }
        return false;
    }

    private Conf asConf() {
        try {
            final String dn = getLdapConfiguration().getString("configurationEntryDN");
            final ErrorResponseFactory errorFactory = ServerUtil.instance(ErrorResponseFactory.class);

            final Conf c = new Conf();
            c.setDn(dn);
            c.setDynamic(ServerUtil.createJsonMapper().writeValueAsString(m_conf));
            c.setErrors(ServerUtil.createJsonMapper().writeValueAsString(errorFactory.getMessages()));
            c.setStatics(ServerUtil.createJsonMapper().writeValueAsString(m_staticConf));
            c.setWebKeys(ServerUtil.createJsonMapper().writeValueAsString(m_jwks));
            return c;
        } catch (Exception e) {
            LOG.warn(e.getMessage(), e);
        }
        return null;
    }

    private void init(Conf p_conf) {
        initConfigurationFromJson(p_conf.getDynamic());
        initStaticConfigurationFromJson(p_conf.getStatics());
        initErrorsFromJson(p_conf.getErrors());
        initWebKeysFromJson(p_conf.getWebKeys());
    }

    private void initWebKeysFromJson(String p_webKeys) {
        try {
            final JSONWebKeySet k = ServerUtil.createJsonMapper().readValue(p_webKeys, JSONWebKeySet.class);
            if (k != null) {
            	m_jwks = k;
            }
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        }
    }

    private void initStaticConfigurationFromJson(String p_statics) {
        try {
            final StaticConf c = ServerUtil.createJsonMapper().readValue(p_statics, StaticConf.class);
            if (c != null) {
            	m_staticConf = c;
            }
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        }
    }

    private void initConfigurationFromJson(String p_configurationJson) {
        try {
            final Configuration c = ServerUtil.createJsonMapper().readValue(p_configurationJson, Configuration.class);
            if (c != null) {
            	m_conf = c;
            }
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        }
    }

    private void initErrorsFromJson(String p_errosAsJson) {
        try {
            final ErrorMessages errorMessages = ServerUtil.createJsonMapper().readValue(p_errosAsJson, ErrorMessages.class);
            if (errorMessages != null) {
                final ErrorResponseFactory f = ServerUtil.instance(ErrorResponseFactory.class);
                f.setMessages(errorMessages);
            }
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
        }
    }

	public void loadLdapConfiguration() {
        try {
            ldapConfiguration = new FileConfiguration(LDAP_FILE_PATH);
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
            ldapConfiguration = null;
        }
	}

    public Configuration loadConfFromFile() {
        try {
            final JAXBContext jc = JAXBContext.newInstance(Configuration.class);
            final Unmarshaller u = jc.createUnmarshaller();
            return (Configuration) u.unmarshal(new File(configFilePath));
        } catch (JAXBException e) {
            LOG.error(e.getMessage(), e);
            return null;
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
            return null;
        }
    }

    private ErrorMessages loadErrorsFromFile() {
        try {
            return ServerUtil.createJsonMapper().readValue(new File(errorsFilePath), ErrorMessages.class);
        } catch (Exception e) {
            LOG.warn(e.getMessage(), e);
        }
        return null;
    }

    private StaticConf loadStaticConfFromFile() {
        try {
            return ServerUtil.createJsonMapper().readValue(new File(staticConfFilePath), StaticConf.class);
        } catch (Exception e) {
            LOG.warn(e.getMessage(), e);
        }
        return null;
    }

    private JSONWebKeySet loadWebKeysFromFile() {
        try {
            return ServerUtil.createJsonMapper().readValue(new File(webKeysFilePath), JSONWebKeySet.class);
        } catch (Exception e) {
            LOG.warn(e.getMessage(), e);
        }
        return null;
    }

    public String loadCryptoConfigurationSalt() {
        try {
            FileConfiguration cryptoConfiguration = createFileConfiguration(saltFilePath, true);

            return cryptoConfiguration.getString("encodeSalt");
        } catch (Exception ex) {
            LOG.error("Failed to load configuration from {0}", ex, saltFilePath);
            throw new ConfigurationException("Failed to load configuration from " + saltFilePath, ex);
        }
    }

    private FileConfiguration createFileConfiguration(String fileName, boolean isMandatory) {
        try {
            FileConfiguration fileConfiguration = new FileConfiguration(fileName);

            return fileConfiguration;
        } catch (Exception ex) {
            if (isMandatory) {
                LOG.error("Failed to load configuration from {0}", ex, fileName);
                throw new ConfigurationException("Failed to load configuration from " + fileName, ex);
            }
        }

        return null;
    }

    /**
	 * Get ConfigurationFactory instance
	 * 
	 * @return ConfigurationFactory instance
	 */
	public static ConfigurationFactory instance() {
        boolean createContexts = !Contexts.isEventContextActive() && !Contexts.isApplicationContextActive();
        if (createContexts) {
            Lifecycle.beginCall();
        }

        return (ConfigurationFactory) Component.getInstance(ConfigurationFactory.class);
	}

}
