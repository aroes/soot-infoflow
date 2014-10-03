package soot.jimple.infoflow.data;

import heros.solver.Pair;

import java.util.ArrayList;
import java.util.Collections;
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
	private List<Stmt> path = null;
	private List<Stmt> callStack = null;
	private int hashCode = 0;
	
	public SourceContextAndPath(Value value, Stmt stmt) {
		this(value, stmt, null);
	}
	
	public SourceContextAndPath(Value value, Stmt stmt, Object userData) {
		super(value, stmt, userData);
	}
	
	public List<Stmt> getPath() {
		return path == null ? Collections.<Stmt>emptyList()
				: Collections.unmodifiableList(this.path);
	}
	
	public SourceContextAndPath extendPath(Stmt s) {
		return extendPath(s, null);
	}
	
	public SourceContextAndPath extendPath(Stmt s, Stmt correspondingCallSite) {
		if (s == null && correspondingCallSite == null)
			return this;
		
		SourceContextAndPath scap = clone();
		if (s != null) {
			if (scap.path == null)
				scap.path = new ArrayList<Stmt>();
			scap.path.add(0, s);
		}
		
		// Extend the call stack
		if (correspondingCallSite != null) {
			if (scap.callStack == null)
				scap.callStack = new ArrayList<Stmt>();
			scap.callStack.add(0, correspondingCallSite);
		}
		
		return scap;
	}
	
	/**
	 * Pops the top item off the call stack.
	 * @return The new {@link SourceContextAndPath} object as the first element
	 * of the pair and the call stack item that was popped off as the second
	 * element. If there is no call stack, null is returned.
	 */
	public Pair<SourceContextAndPath, Stmt> popTopCallStackItem() {
		if (callStack == null || callStack.isEmpty())
			return null;
		
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
		
		if (this.callStack == null) {
			if (scap.callStack != null)
				return false;
		}
		else if (!this.callStack.equals(scap.callStack))
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
					+ 31 * (callStack == null ? 0 : callStack.hashCode())
					+ 31 * super.hashCode();
		}
		return hashCode;
	}
	
	@Override
	public synchronized SourceContextAndPath clone() {
		final SourceContextAndPath scap = new SourceContextAndPath(getValue(), getStmt(), getUserData());
		if (path != null)
			scap.path = new ArrayList<Stmt>(this.path);
		if (callStack != null)
			scap.callStack = new ArrayList<Stmt>(callStack);
		return scap;
	}
	
	@Override
	public String toString() {
		return super.toString() + "\n\ton Path: " + path;
	}	
}
