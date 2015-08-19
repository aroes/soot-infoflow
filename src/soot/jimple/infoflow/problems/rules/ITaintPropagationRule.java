package soot.jimple.infoflow.problems.rules;

import java.util.Collection;

import soot.jimple.Stmt;
import soot.jimple.infoflow.data.Abstraction;

/**
 * Common interface for taint propagation rules
 * 
 * @author Steven Arzt
 *
 */
public interface ITaintPropagationRule {
	
	/**
	 * Propagates a glow along a normal statement this is not a call or return
	 * site
	 * @param d1 The context abstraction
	 * @param source The abstraction to propagate over the statement
	 * @param stmt The statement at which to propagate the abstraction
	 * @return The new abstractions to be propagated to the next statement
	 */
	public Collection<Abstraction> propagateNormalFlow(Abstraction d1,
			Abstraction source, Stmt stmt);

	/**
	 * Propagates a glow along a the call-to-return edge at a call site
	 * @param d1 The context abstraction
	 * @param source The abstraction to propagate over the statement
	 * @param stmt The statement at which to propagate the abstraction
	 * @return The new abstractions to be propagated to the next statement
	 */
	public Collection<Abstraction> propagateCallToReturnFlow(Abstraction d1,
			Abstraction source, Stmt stmt);
	
}
