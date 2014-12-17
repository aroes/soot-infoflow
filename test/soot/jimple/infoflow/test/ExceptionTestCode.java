package soot.jimple.infoflow.test;

import soot.jimple.infoflow.test.android.ConnectionManager;
import soot.jimple.infoflow.test.android.TelephonyManager;

/**
 * Tests for exceptional data- and control flows
 * 
 * @author Steven Arzt
 */
public class ExceptionTestCode {
	
	public void exceptionControlFlowTest1() {
		String tainted = TelephonyManager.getDeviceId();
		try {
			doThrowException();
		}
		catch (RuntimeException ex) {
			ConnectionManager cm = new ConnectionManager();
			cm.publish(tainted);
			System.out.println(ex);
		}
	}

	private void doThrowException() {
		throw new RuntimeException("foo");
	}

}
