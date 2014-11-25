package soot.jimple.infoflow.data;

import heros.solver.Pair;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import soot.jimple.Stmt;
import soot.jimple.infoflow.Infoflow;

/**
 * Extension of {@link SourceContext} that also allows a paths from the source
 * to the current statement to be stored
 * 
 * @author Steven Arzt
 */
public class SourceContextAndPath extends SourceContext implements Cloneable {
	private List<Abstraction> path = null;
	private List<Stmt> callStack = null;
	private int hashCode = 0;
	
	public SourceContextAndPath(AccessPath value, Stmt stmt) {
		this(value, stmt, null);
	}
	
	public SourceContextAndPath(AccessPath value, Stmt stmt, Object userData) {
		super(value, stmt, userData);
	}
	
	public List<Abstraction> getAbstractionPath() {
		return path == null ? Collections.<Abstraction>emptyList()
				: Collections.unmodifiableList(this.path);		
	}
	
	public List<Stmt> getPath() {
		if (path == null)
			return Collections.<Stmt>emptyList();
		List<Stmt> stmtPath = new ArrayList<Stmt>(this.path.size());
		for (Abstraction abs : this.path)
			if (abs.getCurrentStmt() != null)
				stmtPath.add(abs.getCurrentStmt());
		return stmtPath;
	}
	
	public SourceContextAndPath extendPath(Abstraction abs) {
		return extendPath(abs, true);
	}
	
	public SourceContextAndPath extendPath(Abstraction abs, boolean trackPath) {
		if (abs == null || (abs.getCurrentStmt() == null
				&& abs.getCorrespondingCallSite() == null))
			return this;
		
		SourceContextAndPath scap = clone();
		if (trackPath && abs.getCurrentStmt() != null) {
			if (scap.path == null)
				scap.path = new ArrayList<Abstraction>();
			scap.path.add(0, abs);
		}
		
		// Extend the call stack
		if (abs.getCorrespondingCallSite() != null) {
			if (scap.callStack == null)
				scap.callStack = new ArrayList<Stmt>();
			scap.callStack.add(0, abs.getCorrespondingCallSite());
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
		final SourceContextAndPath scap = new SourceContextAndPath(getAccessPath(), getStmt(), getUserData());
		if (path != null)
			scap.path = new ArrayList<Abstraction>(this.path);
		if (callStack != null)
			scap.callStack = new ArrayList<Stmt>(callStack);
		return scap;
	}
	
	@Override
	public String toString() {
		return super.toString() + "\n\ton Path: " + path;
	}	
}
