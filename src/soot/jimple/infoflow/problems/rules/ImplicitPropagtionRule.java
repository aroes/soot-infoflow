package soot.jimple.infoflow.problems.rules;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import soot.Local;
import soot.Value;
import soot.ValueBox;
import soot.jimple.IfStmt;
import soot.jimple.LookupSwitchStmt;
import soot.jimple.Stmt;
import soot.jimple.TableSwitchStmt;
import soot.jimple.infoflow.InfoflowManager;
import soot.jimple.infoflow.aliasing.Aliasing;
import soot.jimple.infoflow.data.Abstraction;
import soot.jimple.infoflow.solver.cfg.IInfoflowCFG.UnitContainer;
import soot.jimple.infoflow.util.ByReferenceBoolean;

/**
 * Rule for propagating implicit taints
 * 
 * @author Steven Arzt
 *
 */
public class ImplicitPropagtionRule extends AbstractTaintPropagationRule {

	public ImplicitPropagtionRule(InfoflowManager manager, Aliasing aliasing,
			Abstraction zeroValue) {
		super(manager, aliasing, zeroValue);
	}

	@Override
	public Collection<Abstraction> propagateNormalFlow(Abstraction d1,
			Abstraction source, Stmt stmt, ByReferenceBoolean killSource,
			ByReferenceBoolean killAll) {
		// Get the operand
		final Value condition;
		if (stmt instanceof IfStmt)
			condition = ((IfStmt) stmt).getCondition();
		else if (stmt instanceof LookupSwitchStmt)
			condition = ((LookupSwitchStmt) stmt).getKey();
		else if (stmt instanceof TableSwitchStmt)
			condition = ((TableSwitchStmt) stmt).getKey();
		else
			return null;
		
		// Check whether we must leave a conditional branch
		if (source.isTopPostdominator(stmt)) {
			source = source.dropTopPostdominator();
			// Have we dropped the last postdominator for an empty taint?
			if (source.getAccessPath().isEmpty() && source.getTopPostdominator() == null) {
				if (killAll != null)
					killAll.value = true;
				return null;
			}
		}
		
		// If we are in a conditionally-called method, there is no
		// need to care about further conditionals, since all
		// assignment targets will be tainted anyway
		if (source.getAccessPath().isEmpty())
			return null;
		
		Set<Value> values = new HashSet<Value>();
		if (condition instanceof Local)
			values.add(condition);
		else
			for (ValueBox box : condition.getUseBoxes())
				values.add(box.getValue());
		
		Set<Abstraction> res = null;									
		for (Value val : values)
			if (getAliasing().mayAlias(val, source.getAccessPath().getPlainValue())) {
				// ok, we are now in a branch that depends on a secret value.
				// We now need the postdominator to know when we leave the
				// branch again.
				UnitContainer postdom = getManager().getICFG().getPostdominatorOf(stmt);
				if (!(postdom.getMethod() == null
						&& source.getTopPostdominator() != null
						&& getManager().getICFG().getMethodOf(postdom.getUnit()) == source.getTopPostdominator().getMethod())) {
					Abstraction newAbs = source.deriveConditionalAbstractionEnter(postdom, stmt);
					
					if (res == null)
						res = new HashSet<Abstraction>();
					res.add(newAbs);
					break;
				}
			}
		
		return res;
	}

	@Override
	public Collection<Abstraction> propagateCallFlow(Abstraction d1,
			Abstraction source, Stmt stmt, ByReferenceBoolean killAll) {
		return null;
	}

	@Override
	public Collection<Abstraction> propagateCallToReturnFlow(Abstraction d1,
			Abstraction source, Stmt stmt, ByReferenceBoolean killSource) {
		return null;
	}

	@Override
	public Collection<Abstraction> propagateReturnFlow(
			Collection<Abstraction> callerD1s, Abstraction source, Stmt stmt) {
		return null;
	}

}
