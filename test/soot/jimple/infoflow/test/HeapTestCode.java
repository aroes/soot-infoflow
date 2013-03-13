package soot.jimple.infoflow.test;

import java.util.ArrayList;

import soot.jimple.infoflow.test.android.ConnectionManager;
import soot.jimple.infoflow.test.android.TelephonyManager;
import soot.jimple.infoflow.test.utilclasses.ClassWithField;

public class HeapTestCode {
	
	public class Y{
		String f;
		
		public void set(String s){
			f = s;
		}
	}
	
	public void simpleTest(){
		String taint = TelephonyManager.getDeviceId();
		Y a = new Y();
		Y b = new Y();
		
		a.set(taint);
		b.set("notaint");
		ConnectionManager cm = new ConnectionManager();
		cm.publish(b.f);
		
	}
	
	public void argumentTest(){
		ClassWithField x = new ClassWithField();
		run(x);
		x.listField = new ArrayList<String>();
		x.listField.add(TelephonyManager.getDeviceId());
		
	}
	
	public static void run(ClassWithField o){
		o = new ClassWithField();
		o.listField = new ArrayList<String>();
		o.listField.add("empty");
		ConnectionManager cm = new ConnectionManager();
		cm.publish(o.field);
		
	}
	
	public void negativeTest(){
		String taint = TelephonyManager.getDeviceId();
		
		MyArrayList notRelevant = new MyArrayList();
		MyArrayList list = new MyArrayList();
		notRelevant.add(taint);
		list.add("test");
		
		ConnectionManager cm = new ConnectionManager();
		cm.publish(list.get());
		
	}
	
	class MyArrayList{
		
		String[] elements;
		
		public void add(String obj){
			if(elements == null){
				elements = new String[3];
			}
			elements[0] = obj;
		}
		
		public String get(){
			return elements[0];
		}
		
	}
	
	public void doubleCallTest(){
		X a = new X();
		X b = new X();
		a.save("neutral");
		b.save(TelephonyManager.getDeviceId());
		ConnectionManager cm = new ConnectionManager();
		cm.publish(String.valueOf(a.e));
	}

	public void methodTest0(){
		String taint = TelephonyManager.getDeviceId();
		X x = new X();
		A a = new A();
		String str = x.xx(a);
		a.b = taint;
		ConnectionManager cm = new ConnectionManager();
		cm.publish(str);
	}
	
	
	class A{
		public String b;
	}
	
	class X{
		public char[] e;
		public String xx(A o){
			return o.b;
		}
		
		public void save(String f){
			e = f.toCharArray();
		}
	}
	
	
	//########################################################################

	public void methodTest1(){
		String tainted = TelephonyManager.getDeviceId();
		 new AsyncTask().execute(tainted);
	}
	
	protected class AsyncTask{
		public Worker mWorker;
		public FutureTask mFuture;
		
		public AsyncTask(){
			mWorker = new Worker(){
				public void call(){
					ConnectionManager cm = new ConnectionManager();
					cm.publish(mParams);
				}
			};
			mFuture = new FutureTask(mWorker);
		}
		
		public void execute(String t){
			mWorker.mParams = t;
	        //shortcut (no executor used):
			//exec.execute(mFuture);
			mFuture.run();
		}
		
	}
	
	protected class Worker{
		public String mParams;
		
		public void call(){
		}
	}
	protected class FutureTask{
		private final Worker wo;
		public FutureTask(Worker w){
			wo = w;
		}
		public void run(){
			wo.call();
		}
	}
}
