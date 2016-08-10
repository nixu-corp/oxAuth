/*
 * oxAuth is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2016, Gluu
 */

package org.gluu.oxauth.resource.custom;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.zip.DataFormatException;

import javax.faces.FacesException;

import org.apache.commons.codec.binary.Base64;
import org.jboss.seam.log.LogProvider;
import org.jboss.seam.log.Logging;
import org.xdi.util.StringHelper;
import org.xdi.zip.CompressionHelper;

import com.sun.facelets.impl.DefaultResourceResolver;

/**
 * External resource handler to customize applicaton 
 *
 * @author Yuriy Movchan Date: 04/05/2016
 */
public class ExternalResourceHandler extends DefaultResourceResolver {

	private static final LogProvider log = Logging.getLogProvider(ExternalResourceHandler.class);

	private File externalResourceBaseFolder;
	private boolean useExternalResourceBase;

	public ExternalResourceHandler() {
		String externalResourceBase = System.getProperty("gluu.external.resource.base");
		if (StringHelper.isNotEmpty(externalResourceBase)) {
			externalResourceBase += "/oxauth/pages";
			File folder = new File(externalResourceBase);
			if (folder.exists() && folder.isDirectory()) {
				this.externalResourceBaseFolder = folder;
				this.useExternalResourceBase = true;
			} else {
				log.error("Specified path '" + externalResourceBase + "' in 'gluu.external.resource.base' not exists or not folder!");
			}
		}
	}

	@Override
	public URL resolveUrl(String path) {
		if (!useExternalResourceBase) {
			return super.resolveUrl(path);
		}

		// First try external resource folder
		final File externalResource = new File(this.externalResourceBaseFolder, path);
		if (externalResource.exists()) {
			try {
				log.debug("Found overriden resource: " + path);
				URL resource = externalResource.toURI().toURL();

				return resource;
			} catch (MalformedURLException ex) {
				throw new FacesException(ex);
			}
		}

		// Return default resource
		return super.resolveUrl(path);
	}

	public String toString() {
		return "ExternalResourceHandler";
	}

	public static void main(String[] args) throws IOException, DataFormatException {
		
		Base64 base64 = new Base64();
		byte[] decoded = base64.decode("fZLNasMwEIRfxehuy/K/hWMozSWQXpqQQy9lLcm1qS0Jr1zSt6/jEJpCyVHSfjPDrCqEcbB8bz7M7F4VWqNReedx0MjXpw2ZJ80NYI9cw6iQO8EPTy97HgUht5NxRpiB3CGPCUBUk+uNJt5uuyHvQrI2SRMpcskiJuJYAEualCV5xGQaxoVsZZRGBSuJd1ITLuSGLEILjjirnUYH2i1XIcv8sPBDdgxLzjKe5m/E2yp0vQa3Up1zFjmlPYxB9+1U8Km+IGh7as4wu45ewvvD2sSirm9tHM0SE+ImTkXZ+iVrSz8pQuGXcZL5UdvIkjV5myogdXWR4Guwqb7ZoRJ+nJWB7s/zxQ370Q7qMrk6RrSXlo7KgQQHge1sRe9lquuGDg7cjH9Pz0Yq7wTDrB53jus0P8xCKERC66vDryj97xfUPw==");
		System.out.println(new String(CompressionHelper.inflate(decoded, true), "UTF-8"));
	}
	
}