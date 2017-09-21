package burp;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class JOOMLA implements IScanIssue{

	IHttpRequestResponse r;
	IHttpRequestResponse[] rr = new IHttpRequestResponse[1];
	URL url;
	String req, res;
	IBurpExtenderCallbacks callback;
    IExtensionHelpers halp;
    int[] reqmarks = new int[2], resmarks = new int[2];
    List<int[]> reqmarkList = new ArrayList<>(1), resmarkList = new ArrayList<>(1);
    IHttpRequestResponse[] rra = new IHttpRequestResponse[1];
	
	public JOOMLA(IHttpRequestResponse r, URL url, IBurpExtenderCallbacks callback, IExtensionHelpers halp)
	{
		this.r = r;
		rr[0] = r;
		this.url = url;
		this.callback = callback;
		this.halp = halp;
		
		//lets create markers
		req = halp.bytesToString(r.getRequest()).toLowerCase();
		res = halp.bytesToString(r.getResponse()).toLowerCase();
				
		reqmarks[0] = req.indexOf("list[fullordering]=updatexml'");
		reqmarks[1] = reqmarks[0] + new String("list[fullordering]=updatexml'").length();
		reqmarkList.add(reqmarks);
				
		resmarks[0] = res.indexOf("you have an error in your sql syntax");
		resmarks[1] = resmarks[0] + new String("you have an error in your sql syntax").length();
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
		return "Joomla - SQL Injection (CVE-2017-8917)";
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
		return "A SQL injection vulnerability in Joomla! CMS 3.7.x before 3.7.1 allows attackers to execute arbitrary SQL commands via user-crafted URL parameters.";
	}

	@Override
	public String getRemediationDetail() {
		return "Update Joomla! CMS to version 3.7.1 or later.";
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
