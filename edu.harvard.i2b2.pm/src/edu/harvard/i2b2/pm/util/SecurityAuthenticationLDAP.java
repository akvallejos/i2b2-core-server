/*
 * Copyright (c) 2011 - University of Texas Health Science Center at Houston.
 * 7000 Fannin St, Suite 600, Houston, Texas 77030
 * All rights reserved.   This program and the accompanying materials
 * are made available under the terms of the i2b2 Software License v2.1
 * which accompanies this distribution.
 */

package edu.harvard.i2b2.pm.util;

import java.util.Hashtable;

import javax.naming.AuthenticationException;
import javax.naming.AuthenticationNotSupportedException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.ldap.*;
import javax.naming.NamingEnumeration;
import javax.naming.directory.SearchResult;
import javax.naming.directory.SearchControls;
import java.io.IOException;




/*
 * LDAP authentication for i2b2 v1.6
 *
 * @param username String
 * @param password String
 * @param params Hashtable object that holds user parameters for LDAP configuration
 *
 * The parameters are listed below with their possible values in ():
 * authentication_method - (LDAP)
 * connection_url - ()
 * search_base - ()
 * distinguished_name - (uid=)
 * ssl - (true)(1)
 * security_authentication - (none), (simple), (DIGEST-MD5), (CRAM-MD5), (EXTERNAL)
 * security_layer - (auth-conf), (auth-int), (auth-conf,auth-int)
 * privacy_strength - (high), (medium), (low)
 * max_buffer - (0)-(65536)
 *
 * @version    1.0 30 Aug 2011
 * @author     Johnny Phan
 * @version    1.1 August 2018
 * @modified   Andrew Vallejos
 *
 * To use TLS the following parameters need to be configured
 * authentication_method - (LDAP)
 * connection_url - (ldap://your.url.here)
 * search_base - (dc=school,dc=edu)
 * service_account - (username)
 * service_account_password - (password)
 * tls - (true)
 *
 * The service account is used to fetch the full DN of the
 * supplied user name.
 * After finding the user's DN we then authenticate using the
 * supplied password.
 *
 */


public class SecurityAuthenticationLDAP implements SecurityAuthentication {

	@Override
	public boolean validateUser(String username, String password,
								Hashtable params) throws Exception {
		String setTLS = "";
		setTLS = (String) params.get("tls");
		setTLS = setTLS.toLowerCase();

		if("true".equals(setTLS)){
			System.out.println("LDAP with TLS used");
			return validateUserTLS(username, password, params);
		} else {
			System.out.println("LDAP without TLS used");
			return validateUserOld(username, password, params);
		}

	}

	private static SearchControls getSimpleSearchControls() {
		SearchControls searchControls = new SearchControls();
		searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
		//searchControls.setTimeLimit(30000);
		//String[] attrIDs = {"objectGUID"};
		//searchControls.setReturningAttributes(attrIDs);
		return searchControls;
	}

	private String find_user(String connectionURL, String distinguish_name, String password, String ds, String samaccountname)
			throws Exception {
		// Set up environment for creating initial context
		Hashtable env = new Hashtable(11);
		env.put(Context.INITIAL_CONTEXT_FACTORY,
				"com.sun.jndi.ldap.LdapCtxFactory");

		// Must use the name of the server that is found in its certificate
		env.put(Context.PROVIDER_URL, connectionURL);

		try {
			LdapContext ctx = new InitialLdapContext(env, null);
			StartTlsResponse tls =
					(StartTlsResponse) ctx.extendedOperation(new StartTlsRequest());
			tls.negotiate();

			ctx.setRequestControls(null);
			ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, distinguish_name);
			ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, password);

			ctx.addToEnvironment(Context.REFERRAL, "follow");
			NamingEnumeration<?> namingEnum = ctx.search(ds, "(samaccountname=" + samaccountname + ")", getSimpleSearchControls());


			while (namingEnum.hasMore ()) {
				SearchResult result = (SearchResult) namingEnum.next ();
				// returns the user's full distinguished name
				System.out.println(result.getNameInNamespace());
				return result.getNameInNamespace();
			}
			namingEnum.close();
			tls.close();
			ctx.close();
		} catch (AuthenticationException authEx) {
			// AUTHENTICATION FAILURE
			throw new Exception(authEx.getMessage());
		} catch (AuthenticationNotSupportedException noSuppEx) {
			// AUTHENTICATION METHOD NOT SUPPORTED
			throw new Exception(noSuppEx.getMessage());
		} catch (NamingException nEx) {
			// NETWORK PROBLEMS?
			throw new Exception(nEx.getMessage());
		} catch (IOException e){
			throw new Exception(e.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			throw new Exception(e.getMessage());
		}

		return "";
	}

	private boolean validateUserOld(String username, String password,
									Hashtable params) throws Exception {

		// Initialize variables
		String connectionURL = "", searchBase = "", securityAuthentication = "",
				setSSL = "", dn = "", principalName = "";

		// DIGEST-MD5 variables
		String securityLayer = "", privacyStrength = "", maxBuffer = "";

		// Sets the values from the parameters
		connectionURL = (String) params.get("connection_url");
		searchBase = (String) params.get("search_base");
		securityAuthentication = (String) params.get("security_authentication");
		securityAuthentication = securityAuthentication.toUpperCase();
		setSSL = (String) params.get("ssl");
		dn = (String) params.get("distinguished_name");
		principalName = dn + username + "," + searchBase;

		// DIGEST-MD5 configuration from the parameters
		securityLayer = (String) params.get("security_layer");
		privacyStrength = (String) params.get("privacy_strength");
		maxBuffer = (String) params.get("max_buffer");

		// Setup environment for creating initial context
		Hashtable env = new Hashtable();
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");

		// URL of the LDAP server(s)
		env.put(Context.PROVIDER_URL, connectionURL);

		// Specify the security authentication
		env.put(Context.SECURITY_AUTHENTICATION, securityAuthentication);

		// Specify SSL
		if (setSSL != null)
			env.put(Context.SECURITY_PROTOCOL, "ssl");

		// Specify the domain name and password
		env.put(Context.SECURITY_PRINCIPAL, principalName);
		env.put(Context.SECURITY_CREDENTIALS, password);

		// DIGEST-MD5 Configurations
		if (securityAuthentication.equalsIgnoreCase("DIGEST-MD5")) {
			if (securityLayer != null)
				env.put("javax.security.sasl.qop", securityLayer);

			if (privacyStrength != null)
				env.put("javax.security.sasl.strength", privacyStrength);

			if (maxBuffer != null)
				env.put("javax.security.sasl.maxbuf", maxBuffer);
		}

		try {
			// Create the initial directory context
			DirContext ctx = new InitialDirContext(env);
			// SUCCESS
			return true;
		} catch(AuthenticationException authEx) {
			// AUTHENTICATION FAILURE
			throw new Exception (authEx.getMessage());
		} catch(AuthenticationNotSupportedException noSuppEx) {
			// AUTHENTICATION METHOD NOT SUPPORTED
			throw new Exception (noSuppEx.getMessage());
		} catch(NamingException nEx) {
			// NETWORK PROBLEMS?
			throw new Exception (nEx.getMessage());
		}


	}

	private boolean validateUserTLS(String username, String password,
									Hashtable params) throws Exception {

		// Initialize variables
		String connectionURL = "", searchBase = "", securityAuthentication = "",
				setSSL = "", dn = "", principalName = "", setTLS = "",
				serviceAccount = "", serviceAccountPwd = "", lockedout = "";

		// Check if user is lockedout
		lockedout = (String) params.get("LOCKEDOUT");
		if("true".equals(lockedout)){
			throw new Exception("This account has been locked. Please contact Please contact the Biomedical Informatics Team at crdw@mcw.edu.");
		}
		// DIGEST-MD5 variables
		String securityLayer = "", privacyStrength = "", maxBuffer = "";

		// Sets the values from the parameters
		connectionURL = (String) params.get("connection_url");
		searchBase = (String) params.get("search_base");
		dn = (String) params.get("distinguished_name");

		// Service Account Details
		serviceAccount = (String) params.get("service_account");
		serviceAccountPwd = (String) params.get("service_account_password");

		try{
			String user_dn = find_user(connectionURL, serviceAccount, serviceAccountPwd, searchBase, username);
			if(user_dn != ""){
				if(find_user(connectionURL, user_dn, password, searchBase, username) != ""){
					return true;
				}
			}
			return false;
		} catch (Exception e){
			throw new Exception(e.getMessage());
			//throw new Exception("Username/Password is incorrect. Please contact help@mcw.edu");
		}
	}
}
