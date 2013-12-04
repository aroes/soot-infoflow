package soot.jimple.infoflow.test;

import soot.jimple.infoflow.test.android.ConnectionManager;

/**
 * Target class for the SourceSinkTests
 * 
 * @author Steven Arzt
 */
public class SourceSinkTestCode {
	
	private class A {
		private String data;
		
		public A(String data) {
			this.data = data;
		}
	}
	
	private A getSecret() {
		return new A("Secret");
	}
	
	public void testDataObject() {
		A a = getSecret();
		ConnectionManager cm = new ConnectionManager();
		cm.publish(a.data);
	}
	
}
