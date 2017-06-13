package soot.jimple.infoflow.memory;

/**
 * Interface that exposes special functions only required by FlowDroid's memory
 * management components
 * 
 * @author Steven Arzt
 *
 */
public interface IMemoryBoundedSolver {
	
	/**
	 * Interface that a memory-bounded solver can use to notify listeners of
	 * status changes
	 * 
	 * @author Steven Arzt
	 *
	 */
	public interface IMemoryBoundedSolverStatusNotification {
		
		/**
		 * Method that is called when the solver has received its first task
		 * @param solver The solver that sends the notification
		 */
		public void notifySolverStarted(IMemoryBoundedSolver solver);
		
		/**
		 * Method that is called when the solver has finished its last task
		 */
		public void notifySolverTerminated(IMemoryBoundedSolver solver);
		
	}
	
	/**
	 * Forces the solver to terminate its tasks and stop processing new tasks.
	 * This will kill the solver.
	 */
	public void forceTerminate();
	
	/**
	 * Checks whether this solver is terminated, either by forced termination,
	 * or because it has finished all of its work.
	 * @return True if this solver is terminated, otherwise false
	 */
	boolean isTerminated();
	
	/**
	 * Checks whether this solver was killed before it could complete its tasks
	 * @return True if this solver was killed before it could complete its
	 * tasks, otherwise false
	 */
	boolean isKilled();
	
	/**
	 * Resets the solver to its initial state after it has been forcefully
	 * terminated. After calling this method, the solver is expected to
	 * accept new tasks.
	 */
	void reset();
	
	/**
	 * Adds a new listener that will be notified of status changes in the solver
	 * @param listener The listener that will be notified when the status of the
	 * solver changes
	 */
	void addStatusListener(IMemoryBoundedSolverStatusNotification listener);

}
