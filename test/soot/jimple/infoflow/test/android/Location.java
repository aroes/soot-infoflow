package soot.jimple.infoflow.test.android;

public class Location {
	
	private double longitude;
	private double latitude;
	
	public Location() {
		
	}
	
	public Location(double longitude, double latitude) {
		this.longitude = longitude;
		this.latitude = latitude;
	}
	
	public double getLongitude() {
		return this.longitude;
	}
	
	public double getLatitude() {
		return this.latitude;
	}

}
