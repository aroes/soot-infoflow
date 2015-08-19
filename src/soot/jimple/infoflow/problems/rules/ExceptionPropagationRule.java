package soot.jimple.infoflow.problems.rules;

import java.util.Collection;
import java.util.Collections;

import soot.jimple.CaughtExceptionRef;
import soot.jimple.DefinitionStmt;
import soot.jimple.Stmt;
import soot.jimple.ThrowStmt;
import soot.jimple.infoflow.InfoflowManager;
import soot.jimple.infoflow.aliasing.Aliasing;
import soot.jimple.infoflow.data.Abstraction;

/**
 * Rule for propagating exceptional data flows
 * 
 * @author Steven Arzt
 *
 */
public class ExceptionPropagationRule extends AbstractTaintPropagationRule {

	public ExceptionPropagationRule(InfoflowManager manager, Aliasing aliasing,
			Abstraction zeroValue) {
		super(manager, aliasing, zeroValue);
	}

	@Override
	public Collection<Abstraction> propagateNormalFlow(Abstraction d1,
			Abstraction source, Stmt stmt) {
		if (source == getZeroValue())
			return null;
		
		// Do we catch an exception here?
		if (source.getExceptionThrown() && stmt instanceof DefinitionStmt) {
			DefinitionStmt def = (DefinitionStmt) stmt;
			if (def.getRightOp() instanceof CaughtExceptionRef)
				return Collections.singleton(source.deriveNewAbstractionOnCatch(def.getLeftOp()));
		}
		
		// Do we throw an exception here?
		if (stmt instanceof ThrowStmt) {
			ThrowStmt throwStmt = (ThrowStmt) stmt;
			if (getAliasing().mayAlias(throwStmt.getOp(), source.getAccessPath().getPlainValue()))
				return Collections.singleton(source.deriveNewAbstractionOnThrow(throwStmt));
		}
		
		return Collections.singleton(source);
	}

	@Override
	public Collection<Abstraction> propagateCallToReturnFlow(Abstraction d1,
			Abstraction source, Stmt stmt) {
		// We don't need to do anything here
		return null;
	}

	@Override
	public Collection<Abstraction> propagateReturnFlow(Collection<Abstraction> callerD1s,
			Abstraction source, Stmt stmt) {
		// If we throw an exception with a tainted operand, we need to
		// handle this specially
		if (stmt instanceof ThrowStmt) {
			ThrowStmt throwStmt = (ThrowStmt) stmt;
			if (getAliasing().mayAlias(throwStmt.getOp(), source.getAccessPath().getPlainValue()))
				return Collections.singleton(source.deriveNewAbstractionOnThrow(throwStmt));
		}
		
		return null;
	}

}
