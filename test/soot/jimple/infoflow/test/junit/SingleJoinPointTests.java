package soot.jimple.infoflow.test.junit;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import soot.jimple.infoflow.IInfoflow;
import soot.jimple.infoflow.data.pathBuilders.DefaultPathBuilderFactory;
import soot.jimple.infoflow.data.pathBuilders.DefaultPathBuilderFactory.PathBuilder;

/**
 * Tests for the "single join point abstraction" option
 * 
 * @author Steven Arzt
 *
 */
public class SingleJoinPointTests extends JUnitTests {
	
    @Test(timeout=300000)
    public void sharedMethodTest1(){
    	System.out.println("Running test case sharedMethodTest1...");
    	IInfoflow infoflow = initInfoflow();
		infoflow.getConfig().setSingleJoinPointAbstraction(true);
		
    	List<String> epoints = new ArrayList<String>();
    	epoints.add("<soot.jimple.infoflow.test.SingleJoinPointTestCode: void sharedMethodTest1()>");
		infoflow.computeInfoflow(appPath, libPath, epoints, sources, sinks);

		checkInfoflow(infoflow, 2);
		System.out.println("Test case sharedMethodTest1 done.");
    }

    @Test(timeout=300000)
    public void sharedMethodTest1b(){
    	System.out.println("Running test case sharedMethodTest1b...");
    	IInfoflow infoflow = initInfoflow(false,
    			new DefaultPathBuilderFactory(PathBuilder.ContextSensitive, true));
		infoflow.getConfig().setSingleJoinPointAbstraction(true);
		
    	List<String> epoints = new ArrayList<String>();
    	epoints.add("<soot.jimple.infoflow.test.SingleJoinPointTestCode: void sharedMethodTest1()>");
		infoflow.computeInfoflow(appPath, libPath, epoints, sources, sinks);

		checkInfoflow(infoflow, 2);
		System.out.println("Test case sharedMethodTest1b done.");
    }

    @Test(timeout=300000)
    public void sharedMethodTest1c(){
    	System.out.println("Running test case sharedMethodTest1c...");
    	IInfoflow infoflow = initInfoflow(false,
    			new DefaultPathBuilderFactory(PathBuilder.ContextInsensitiveSourceFinder, false));
		infoflow.getConfig().setSingleJoinPointAbstraction(true);
		
    	List<String> epoints = new ArrayList<String>();
    	epoints.add("<soot.jimple.infoflow.test.SingleJoinPointTestCode: void sharedMethodTest1()>");
		infoflow.computeInfoflow(appPath, libPath, epoints, sources, sinks);

		checkInfoflow(infoflow, 2);
		System.out.println("Test case sharedMethodTest1c done.");
    }

}
