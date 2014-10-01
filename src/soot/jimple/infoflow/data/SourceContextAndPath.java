package soot.jimple.infoflow.data;

import heros.solver.Pair;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import soot.Value;
import soot.jimple.Stmt;
import soot.jimple.infoflow.Infoflow;

/**
 * Extension of {@link SourceContext} that also allows a paths from the source
 * to the current statement to be stored
 * 
 * @author Steven Arzt
 */
public class SourceContextAndPath extends SourceContext implements Cloneable {
	private final List<Stmt> path = new LinkedList<Stmt>();
	private final List<Stmt> callStack = new ArrayList<Stmt>();
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
		if (s == null && correspondingCallSite == null)
			return this;
		
		SourceContextAndPath scap = clone();
		if (s != null)
			scap.path.add(0, s);
		
		// Extend the call stack
		if (correspondingCallSite != null)
			scap.callStack.add(0, correspondingCallSite);
		
		return scap;
	}
	
	/*
	public boolean putAbstractionOnCallStack(Abstraction abs) {
		for (Pair<Stmt, Set<Abstraction>> callPair : callStack)
			if (callPair.getO2().contains(abs))
				return false;
		
		synchronized (this) {
			Pair<Stmt, Set<Abstraction>> stackTop = null;
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
	*/
	
	/**
	 * Pops the top item off the call stack.
	 * @return The new {@link SourceContextAndPath} object as the first element
	 * of the pair and the call stack item that was popped off as the second
	 * element. If there is no call stack, null is returned.
	 */
	public Pair<SourceContextAndPath, Stmt> popTopCallStackItem() {
		if (callStack.isEmpty())
			return null;
		
		/*
		// If we only have the null item on the call stack, we keep the current
		// object. This avoids creating unnecessary clones.
		if (callStack.peek() == null)
			return null;
		*/
		
		SourceContextAndPath scap = clone();
		return new Pair<>(scap, scap.callStack.remove(0));
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
		
		if (!this.callStack.equals(scap.callStack))
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
			hashCode = (!Infoflow.getPathAgnosticResults() ? 31 * path.hashCode() : 0)
					+ 31 * callStack.hashCode()
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
