package org.lu.pkcs7.cms.tests;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * 
 * @author Igor Konovalov ikonovalov@luxoft.com
 *
 */
public class CLIParser {
	
	public static final String ENCRYPTED_FILE = "-ef";
	
	public static final String DECRYPTED_FILE = "-df";
	
	public static final String CONTAINER_ALIAS = "-c";
	
	public static final String CONTAINER_PASSWORD = "-p";
	
	public static final String SHOW_SIGNED = "-ss";
	
	private Map<String, String> params = new HashMap<String, String>(5);
	
	private static final String VESION = "1.0.0";
	
	public void init(String[] args) {
		// welcome --------
		System.out.println("Luxoft. JCP test.");
		System.out.println("Version " + VESION);
		// show help ------
		List<String> all = Arrays.asList(args);
		if (all.contains("-h") || all.contains("--help") || all.contains("-?") || all.contains("?")) {
			System.out.println("\t{key}\t{desc}");
			System.out.println("\t" + ENCRYPTED_FILE + "\tpath to encrypted file");
			System.out.println("\t[" + DECRYPTED_FILE + "]\twhere message will be stored. If not specified - will be printed only");
			System.out.println("\t" + CONTAINER_ALIAS + "\tContainer with private key");
			System.out.println("\t[" + CONTAINER_PASSWORD + "]\tContainer password. If needed.");
			System.exit(0);
		}
		//-----------------
		
		if (args.length % 2 != 0) throw new IllegalArgumentException("Wrong parameters number");
		for (int z = 0; z < args.length; z+=2) {
			params.put(args[z], args[z+1]);
		}
	}
	
	public boolean contains(String key) {
		return params.containsKey(key);
	}
	
	public String getParam(String key) {
		return params.get(key);
	}

	@Override
	public String toString() {

		return "CLIParser [params=" + params + "]";
	}
	
	

}
