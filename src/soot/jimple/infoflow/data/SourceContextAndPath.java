package soot.jimple.infoflow.data;

import heros.solver.Pair;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import soot.Value;
import soot.jimple.Stmt;
import soot.jimple.infoflow.Infoflow;

import com.google.common.collect.Sets;

/**
 * Extension of {@link SourceContext} that also allows a paths from the source
 * to the current statement to be stored
 * 
 * @author Steven Arzt
 */
public class SourceContextAndPath extends SourceContext implements Cloneable {
	private final List<Stmt> path = new LinkedList<Stmt>();
	private final List<Pair<Stmt, Set<Abstraction>>> callStack = new ArrayList<Pair<Stmt, Set<Abstraction>>>();
	private int hashCode = 0;
	
	public SourceContextAndPath(Value value, Stmt stmt) {
		this(value, stmt, null);
	}
	
	public SourceContextAndPath(Value value, Stmt stmt, Object userData) {
		super(value, stmt, userData);
	}
	
	public List<Stmt> getPath() {
		return Collections.unmodifiableList(this.path);
	}
	
	public SourceContextAndPath extendPath(Stmt s) {
		return extendPath(s, null);
	}
	
	public SourceContextAndPath extendPath(Stmt s, Stmt correspondingCallSite) {
		if (s == null)
			return this;
		
		SourceContextAndPath scap = clone();
		scap.path.add(0, s);
		
		// Extend the call stack
		if (correspondingCallSite != null)
			scap.callStack.add(0, new Pair<Stmt, Set<Abstraction>>(correspondingCallSite,
					Sets.<Abstraction>newIdentityHashSet()));
		
		return scap;
	}
	
	public boolean putAbstractionOnCallStack(Abstraction abs) {
		for (Pair<Stmt, Set<Abstraction>> callPair : callStack)
			if (callPair.getO2().contains(abs))
				return false;

		Pair<Stmt, Set<Abstraction>> stackTop = null;
		synchronized (this) {
			if (callStack.isEmpty()) {
				stackTop = new Pair<Stmt, Set<Abstraction>>(null,
						Sets.<Abstraction>newIdentityHashSet());
				callStack.add(0, stackTop);
			}
			else
				stackTop = callStack.get(0);
			
			return stackTop.getO2().add(abs);
		}
	}
	
	/**
	 * Pops the top item off the call stack.
	 * @return The new {@link SourceContextAndPath} object as the first element
	 * of the pair and the call stack item that was popped off as the second
	 * element
	 */
	public Pair<SourceContextAndPath, Pair<Stmt, Set<Abstraction>>> popTopCallStackItem() {
		if (callStack.isEmpty())
			return new Pair<>(this, null);
		
		SourceContextAndPath scap = clone();
		Pair<Stmt, Set<Abstraction>> csi = scap.callStack.remove(0);
		return new Pair<>(scap, csi);
	}
	
	/**
	 * Pops the top item off the call stack. Note that this method modifies the
	 * state of the current object. The caller is responsible for making sure
	 * that the object is not used anywhere and that the immutability contract
	 * is not violated.  
	 * @return The call stack item that was popped off
	 */
	public Pair<Stmt, Set<Abstraction>> _popTopCallStackItem() {
		return callStack.isEmpty() ? null : callStack.remove(0);
	}
	
	@Override
	public boolean equals(Object other) {
		if (this == other)
			return true;
		if (other == null || getClass() != other.getClass())
			return false;
		SourceContextAndPath scap = (SourceContextAndPath) other;
		
		if (this.hashCode != 0 && scap.hashCode != 0 && this.hashCode != scap.hashCode)
			return false;
		
		if (this.callStack.size() != scap.callStack.size())
			return false;
		for (int i = 0; i < scap.callStack.size(); i++)
			if (this.callStack.get(i).getO1() != scap.callStack.get(i).getO1())
				return false;
		
		if (!Infoflow.getPathAgnosticResults() && !this.path.equals(scap.path))
			return false;
		
		return super.equals(other);
	}
	
	@Override
	public int hashCode() {
		if (hashCode != 0)
			return hashCode;
		
		synchronized(this) {
			int callStackHash = 31 * callStack.size();
			for (Pair<Stmt, Set<Abstraction>> entry : callStack)
				callStackHash += 31 * (entry.getO1() == null ? 0 : entry.getO1().hashCode());
			
			hashCode = (!Infoflow.getPathAgnosticResults() ? 31 * path.hashCode() : 0)
					+ 31 * callStackHash
					+ 31 * super.hashCode();
		}
		return hashCode;
	}
	
	@Override
	public synchronized SourceContextAndPath clone() {
		final SourceContextAndPath scap = new SourceContextAndPath(getValue(), getStmt(), getUserData());
		scap.path.addAll(this.path);
		scap.callStack.addAll(callStack);
		return scap;
	}
	
	@Override
	public String toString() {
		return super.toString() + "\n\ton Path: " + path;
	}	
}
