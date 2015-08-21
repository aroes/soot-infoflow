package soot.jimple.infoflow.problems.rules;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import soot.Local;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.DefinitionStmt;
import soot.jimple.FieldRef;
import soot.jimple.IfStmt;
import soot.jimple.LookupSwitchStmt;
import soot.jimple.Stmt;
import soot.jimple.TableSwitchStmt;
import soot.jimple.infoflow.InfoflowManager;
import soot.jimple.infoflow.aliasing.Aliasing;
import soot.jimple.infoflow.collect.ConcurrentHashSet;
import soot.jimple.infoflow.collect.MyConcurrentHashMap;
import soot.jimple.infoflow.data.Abstraction;
import soot.jimple.infoflow.data.AccessPath;
import soot.jimple.infoflow.solver.cfg.IInfoflowCFG.UnitContainer;
import soot.jimple.infoflow.util.ByReferenceBoolean;

/**
 * Rule for propagating implicit taints
 * 
 * @author Steven Arzt
 *
 */
public class ImplicitPropagtionRule extends AbstractTaintPropagationRule {

    private final MyConcurrentHashMap<Unit, Set<Abstraction>> implicitTargets =
    		new MyConcurrentHashMap<Unit, Set<Abstraction>>();
    
    public ImplicitPropagtionRule(InfoflowManager manager, Aliasing aliasing,
			Abstraction zeroValue) {
		super(manager, aliasing, zeroValue);
	}

	@Override
	public Collection<Abstraction> propagateNormalFlow(Abstraction d1,
			Abstraction source, Stmt stmt, ByReferenceBoolean killSource,
			ByReferenceBoolean killAll) {
		// Do not process zero abstractions
		if (source == getZeroValue())
			return null;
		
		// Check whether we must leave a conditional branch
		if (leavesConditionalBranch(stmt, source, killAll))
			return null;
		
		// We only consider active abstractions
		if (!source.isAbstractionActive())
			return null;
		
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
	
	/**
	 * Checks whether the given abstraction at the given statement leaves a
	 * conditional branch
	 * @param stmt The statement to check
	 * @param source The abstraction arriving at the given statement
	 * @param killAll The by-value boolean to receive whether all taints shall
	 * be removed
	 * @return True if the given abstraction at the given statement leaves a
	 * conditional branch, otherwise false
	 */
	private boolean leavesConditionalBranch(Stmt stmt, Abstraction source,
			ByReferenceBoolean killAll) {
		// Check whether we must leave a conditional branch
		if (source.isTopPostdominator(stmt)) {
			source = source.dropTopPostdominator();
			// Have we dropped the last postdominator for an empty taint?
			if (source.getAccessPath().isEmpty() && source.getTopPostdominator() == null) {
				if (killAll != null)
					killAll.value = true;
				return true;
			}
		}
		return false;
	}

	@Override
	public Collection<Abstraction> propagateCallFlow(Abstraction d1,
			Abstraction source, Stmt stmt, ByReferenceBoolean killAll) {
		// Do not process zero abstractions
		if (source == getZeroValue())
			return null;
		
		// Check whether we must leave a conditional branch
		if (leavesConditionalBranch(stmt, source, killAll))
			return null;
		
		// If we have already tracked implicit flows through this method,
		// there is no point in tracking explicit ones afterwards as well.
		if (implicitTargets.containsKey(stmt) && (d1 == null || implicitTargets.get(stmt).contains(d1))) {
			if (killAll != null)
				killAll.value = true;
			return null;
		}
		
		// If no parameter is tainted, but we are in a conditional, we create a
		// pseudo abstraction. We do not map parameters if we are handling an
		// implicit flow anyway.
		if (source.getAccessPath().isEmpty()) {
			// Block the call site for further explicit tracking
			if (d1 != null) {
				Set<Abstraction> callSites = implicitTargets.putIfAbsentElseGet
						(stmt, new ConcurrentHashSet<Abstraction>());
				callSites.add(d1);
			}
			
			Abstraction abs = source.deriveConditionalAbstractionCall(stmt);
			return Collections.singleton(abs);
		}
		// If we are already inside a conditional call, we don't need to
		// propagate anything
		else if (source.getTopPostdominator() != null) {
			if (killAll != null)
				killAll.value = true;
			return null;
		}
				
		return null;
	}

	@Override
	public Collection<Abstraction> propagateCallToReturnFlow(Abstraction d1,
			Abstraction source, Stmt stmt, ByReferenceBoolean killAll) {
		// Do not process zero abstractions
		if (source == getZeroValue())
			return null;
		
		// Check whether we must leave a conditional branch
		if (leavesConditionalBranch(stmt, source, killAll))
			return null;
		
		// Implicit flows: taint return value
		if (stmt instanceof DefinitionStmt) {
			// If we have an implicit flow, but the assigned
			// local is never read outside the condition, we do
			// not need to taint it.
			boolean implicitTaint = source.getTopPostdominator() != null
					&& source.getTopPostdominator().getUnit() != null;							
			implicitTaint |= source.getAccessPath().isEmpty();
			
			if (implicitTaint) {
				Value leftVal = ((DefinitionStmt) stmt).getLeftOp();
				
				// We can skip over all local assignments inside conditionally-
				// called functions since they are not visible in the caller
				// anyway
				if ((d1 == null || d1.getAccessPath().isEmpty())
						&& !(leftVal instanceof FieldRef))
					return null;
				
				Abstraction abs = source.deriveNewAbstraction(new AccessPath(leftVal, true), stmt);
				return Collections.singleton(abs);
			}
		}
		return null;
	}

	@Override
	public Collection<Abstraction> propagateReturnFlow(
			Collection<Abstraction> callerD1s, Abstraction source, Stmt stmt,
			Stmt retSite) {
		return null;
	}

}
