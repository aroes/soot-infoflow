package soot.jimple.infoflow.solver;

import soot.jimple.toolkits.ide.icfg.BackwardsInterproceduralCFG;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;


public class BackwardsInfoflowCFG extends InfoflowCFG {

	public BackwardsInfoflowCFG() {
		super(new BackwardsInterproceduralCFG(new JimpleBasedInterproceduralCFG()));
	}
	
}
