// Wappalyzer by ElbertF 2009 http://elbertf.com

var wappalyzer = {};

addEventListener('load',   function() { wappalyzer.init();       }, false);
addEventListener('unload', function() { wappalyzer.sendReport(); }, false);

wappalyzer =
{
	apps:           {},
	appsDetected:   0,
	autoDetect:     true,
	browser:        {},
	currentTab:     false,
	checkUnique:    {},
	enableTracking: true,
	history:        {},
	hitCount:       0,
	homeUrl:        'http://wappalyzer.com/',
	isBookmarklet:  false,
	isMobile:       false,
	newInstall:     false,
	prevUrl:        '',
	prefs:          {},
	regexDomain:    /^[a-z0-9._\-]+\.[a-z]+/,
	req:            false,
	request:        false,
	showAppNames:   3,

	init: function()
	{
		wappalyzer.log('init');

		wappalyzer.browser = typeof(Browser) != 'undefined' ? Browser.selectedBrowser : gBrowser;

		// Preferences
		wappalyzer.prefs = Components.classes['@mozilla.org/preferences-service;1'].getService(Components.interfaces.nsIPrefService).getBranch('wappalyzer.');

		wappalyzer.prefs.QueryInterface(Components.interfaces.nsIPrefBranch2);
		wappalyzer.prefs.addObserver('', wappalyzer, false);

		wappalyzer.showAppNames   = wappalyzer.prefs.getIntPref( 'showAppNames');
		wappalyzer.autoDetect     = wappalyzer.prefs.getBoolPref('autoDetect');
		wappalyzer.enableTracking = wappalyzer.prefs.getBoolPref('enableTracking');
		wappalyzer.newInstall     = wappalyzer.prefs.getBoolPref('newInstall');

		var locationPref = wappalyzer.prefs.getIntPref('location');

		wappalyzer.moveLocation(locationPref);

		// Open page after installation
		if ( wappalyzer.newInstall )
		{
			wappalyzer.prefs.setBoolPref('newInstall', false);

			wappalyzer.browser.addEventListener('load', wappalyzer.installSuccess, false);
		}

		if ( typeof(messageManager) != 'undefined' )
		{
			// Listen messages sent from the content process
			messageManager.addMessageListener('wappalyzer:onPageLoad', wappalyzer.onContentPageLoad);

			messageManager.loadFrameScript('chrome://wappalyzer/content/content.js', true);
		}

		// Listen for URL changes
		wappalyzer.browser.addProgressListener(wappalyzer.urlChange, Components.interfaces.nsIWebProgress.NOTIFY_LOCATION);

		// Listen for page loads
		wappalyzer.browser.addEventListener('DOMContentLoaded', wappalyzer.onPageLoad, true);
	},

	log: function(message) {
		//return;

		var consoleService = Components.classes["@mozilla.org/consoleservice;1"].getService(Components.interfaces.nsIConsoleService);

		consoleService.logStringMessage("Wappalyzer: " + message);
	},

	get strings()
	{
		return document.getElementById('wappalyzer-strings');
	},

	observe: function(subject, topic, data)
	{
		if ( topic != 'nsPref:changed' )
		{
			return;
		}

		switch(data)
		{
			case 'autoDetect':
				wappalyzer.autoDetect = wappalyzer.prefs.getBoolPref('autoDetect');

				break;
			case 'enableTracking':
				wappalyzer.enableTracking = wappalyzer.prefs.getBoolPref('enableTracking');

				break;
			case 'showAppNames':
				wappalyzer.showAppNames = wappalyzer.prefs.getIntPref('showAppNames');

				break;
			case 'location':
				var locationPref = wappalyzer.prefs.getIntPref('location');

				wappalyzer.moveLocation(locationPref);
		}
	},

	moveLocation: function(locationPref) {
		wappalyzer.log('moveLocation');

		var containerId = 'urlbar-icons';

		switch ( locationPref )
		{
			case 1:
				containerId = 'wappalyzer-statusbar';

				break;
		}

		var e         = document.getElementById(containerId);
		var container = document.getElementById('wappalyzer-container');

		e.appendChild(container);
	},

	onPageLoad: function(event)
	{
		wappalyzer.log('onPageLoad');

		var doc = event.originalTarget;

		if ( !doc.request )
		{
			wappalyzer.request = false;
		}

		wappalyzer.analyzePage(
			doc.location.href,
			doc.documentElement.innerHTML,
			[],
			true,
			false
			);
	},

	onContentPageLoad: function(message)
	{
		wappalyzer.log('onContentPageLoad');

		wappalyzer.analyzePage(
			message.json.href,
			message.json.html,
			message.json.headers,
			true,
			false
			);
	},

	onUrlChange: function(request)
	{
		wappalyzer.log('onUrlChange');

		wappalyzer.clearDetectedApps();

		var doc = wappalyzer.browser.contentDocument;

		if ( !doc.request )
		{
			doc.request = request;
		}

		wappalyzer.request = doc.request;

		wappalyzer.currentTab = false;

		wappalyzer.analyzePage(
			doc.location.href   ? doc.location.href             : '',
			doc.documentElement ? doc.documentElement.innerHTML : '',
			[],
			false,
			false
			);
	},

	urlChange:
	{
		QueryInterface: function(iid)
		{
			if ( iid.equals(Components.interfaces.nsIWebProgressListener)   ||
			     iid.equals(Components.interfaces.nsISupportsWeakReference) ||
			     iid.equals(Components.interfaces.nsISupports) )
			{
				return this;
			}

			throw Components.results.NS_NOINTERFACE;
		},

		onLocationChange: function(progress, request, url)
		{
			wappalyzer.log('urlChange.onLocationChange');

			if ( !url )
			{
				wappalyzer.prevUrl = '';

				return;
			}

			if ( url.spec != wappalyzer.prevUrl )
			{
				wappalyzer.prevUrl = url.spec;

				wappalyzer.onUrlChange(request);
			}
		},

		onStateChange:    function(a, b, c, d)       {},
		onProgressChange: function(a, b, c, d, e, f) {},
		onStatusChange:   function(a, b, c, d)       {},
		onSecurityChange: function(a, b, c)          {}
	},

	analyzePage: function(href, html, headers, doCount, manualDetect)
	{
		wappalyzer.log('analyzePage');

		wappalyzer.currentTab = false;

		if ( !wappalyzer.isBookmarklet )
		{
			if ( href == wappalyzer.browser.contentDocument.location.href )
			{
				wappalyzer.currentTab = true;

				wappalyzer.clearDetectedApps();
			}
		}

		if ( typeof(html) == 'undefined' )
		{
			html = '';
		}

		if ( wappalyzer.autoDetect || ( !wappalyzer.autoDetect && manualDetect ) )
		{
			// Scan URL, domain and response headers for patterns
			if ( html.length > 50000 ) // Prevent large documents from slowing things down
			{
				html = html.substring(0, 25000) + html.substring(html.length - 25000, html.length);
			}

			if ( html )
			{
				for ( var appName in wappalyzer.apps )
				{
					if ( typeof(wappalyzer.checkUnique[appName]) == 'undefined' ) // Don't scan for apps that have already been detected
					{
						// Scan HTML
						if ( typeof(wappalyzer.apps[appName].html) != 'undefined' )
						{
							var regex = wappalyzer.apps[appName].html;

							if ( regex.test(html) )
							{
								wappalyzer.showApp(appName, href, doCount);
							}
						}

						// Scan URL
						if ( href && typeof(wappalyzer.apps[appName].url) != 'undefined' )
						{
							var regex = wappalyzer.apps[appName].url;

							if ( regex.test(href) )
							{
								wappalyzer.showApp(appName, href, doCount);
							}
						}

						// Scan response header
						if ( typeof(wappalyzer.apps[appName].headers) != 'undefined' && wappalyzer.request )
						{
							for ( var header in wappalyzer.apps[appName].headers )
							{
								var regex = wappalyzer.apps[appName].headers[header];

								try
								{
									if ( regex.test(wappalyzer.request.nsIHttpChannel.getResponseHeader(header)) )
									{
										wappalyzer.showApp(appName, href, doCount);
									}
								}
								catch(e)
								{
								}
							}
						}
					}
				}
			}

			html = ''; // Free memory
		}
	},

	showApp: function(detectedApp, href, doCount)
	{
		wappalyzer.log('showApp ' + detectedApp);

		if ( !wappalyzer.currentTab && !wappalyzer.isBookmarklet )
		{
			wappalyzer.report(detectedApp, href);

			return;
		}

		if ( detectedApp && typeof(wappalyzer.checkUnique[detectedApp]) == 'undefined' )
		{
			switch ( true )
			{
				case wappalyzer.isBookmarklet:
					var e = document.getElementById('wappalyzer-bookmarklet-apps');

					e.innerHTML =
						( wappalyzer.appsDetected ? e.innerHTML : '' ) +
						'<a href="' + wappalyzer.homeUrl + 'stats/app/' + escape(wappalyzer.app[i]) + '" style="color: #332;">' +
						wappalyzer.app[i] +
						'</a><br/>'
						;

					break;
				case wappalyzer.isMobile:
				default:
					// Hide Wappalyzer icon
					document.getElementById('wappalyzer-icon').style.display = 'none';

					// Show app icon and label
					var e = document.getElementById('wappalyzer-detected-apps');

					var child = document.createElement('image');

					child.setAttribute('src',   'chrome://wappalyzer/skin/app_icons/' + detectedApp + '.ico');
					child.setAttribute('class', 'wappalyzer-icon');

					if ( !wappalyzer.isMobile )
					{
						if ( wappalyzer.showAppNames == 2 )
						{
							var container = document.getElementById('wappalyzer-container');

							var tooltiptext = container.getAttribute('tooltiptext') + '\n' + detectedApp;

							container.setAttribute('tooltiptext', tooltiptext);
						}

						if ( wappalyzer.showAppNames == 3 )
						{
							child.setAttribute('onmouseover', 'wappalyzer.showLabels(true)');
							child.setAttribute('onmouseout',  'wappalyzer.showLabels(false)');
						}

						if ( wappalyzer.appsDetected )
						{
							child.setAttribute('style', 'margin-left: .5em');
						}
					}

					e.appendChild(child);

					if ( !wappalyzer.isMobile )
					{
						child = document.createElement('label');

						child.setAttribute('value', detectedApp);
						child.setAttribute('class', 'wappalyzer-app-name');

						if ( wappalyzer.showAppNames != 1 )
						{
							child.setAttribute('style', 'display: none;');
						}

						if ( wappalyzer.showAppNames == 3 )
						{
							child.setAttribute('onmouseover', 'wappalyzer.showLabels(true)');
							child.setAttribute('onmouseout',  'wappalyzer.showLabels(false)');
						}

						e.appendChild(child);

						// Enable application statistics menu item
						var e = document.getElementById('wappalyzer-app-stats');

						e.parentNode.setAttribute('disabled', false);

						var child = document.createElement('menuitem');

						child.setAttribute('label',     detectedApp);
						child.setAttribute('class',     'menuitem-iconic');
						child.setAttribute('type',      '');
						child.setAttribute('image',     'chrome://wappalyzer/skin/app_icons/' + detectedApp + '.ico');
						child.setAttribute('oncommand', 'wappalyzer.openTab(\'' + wappalyzer.homeUrl + 'stats/app/' + escape(detectedApp) + '\');');

						e.appendChild(child);
					}
			}

			if ( doCount )
			{
				wappalyzer.report(detectedApp, href);
			}

			wappalyzer.appsDetected ++;

			wappalyzer.checkUnique[detectedApp] = true;
		}
	},

	report: function(detectedApp, href)
	{
		wappalyzer.log('report');

		domain = href.match(/:\/\/(.[^/]+)/)[1];

		if ( wappalyzer.enableTracking && wappalyzer.regexDomain.test(domain) )
		{
			if ( typeof(wappalyzer.history[domain]) == 'undefined' )
			{
				wappalyzer.history[domain] = [];
			}

			if ( typeof(wappalyzer.history[domain][detectedApp]) == 'undefined' )
			{
				wappalyzer.history[domain][detectedApp] = 0;
			}

			wappalyzer.history[domain][detectedApp] ++;

			wappalyzer.hitCount ++;

			if ( wappalyzer.hitCount > 100 )
			{
				wappalyzer.sendReport();
			}
		}
	},

	sendReport: function()
	// Anonymously send the name of the detected apps and domains to wappalyzer.com
	// You can turn this off in the options dialog
	// This is used to track the distibution of software, stats are publically available on the site
	{
		wappalyzer.log('sendReport');

		if ( wappalyzer.enableTracking && !wappalyzer.req )
		{
			var report = '';

			var i, j;

			if ( wappalyzer.history )
			{
				for ( i in wappalyzer.history )
				{
					report += '[' + i;

					for ( j in wappalyzer.history[i] )
					{
						report += '|' + j + ':' + wappalyzer.history[i][j];
					}

					report += ']';
				}
			}

			// Make POST request
			wappalyzer.req = new XMLHttpRequest();

			wappalyzer.req.open('POST', wappalyzer.homeUrl + 'report/', true);

			wappalyzer.req.channel.loadFlags |= Components.interfaces.nsIRequest.LOAD_BYPASS_CACHE;

			wappalyzer.req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');

			wappalyzer.req.onreadystatechange = function(e)
			{
				if ( wappalyzer.req.readyState == 4 )
				{
					if ( wappalyzer.req.status == 200 )
					{
						// Reset
						report = '';

						wappalyzer.hitCount = 0;
						wappalyzer.history  = [];
					}

					wappalyzer.req.close();

					wappalyzer.req = false;
				}
			};

			wappalyzer.req.send('d=' + encodeURIComponent(report));
		}
	},

	clearDetectedApps: function()
	{
		wappalyzer.log('clearDetectedApps');

		wappalyzer.appsDetected = 0;
		wappalyzer.checkUnique  = [];

		// Show Wappalyzer icon
		document.getElementById('wappalyzer-icon').style.display = '';

		// Clear app icons and labels
		e = document.getElementById('wappalyzer-detected-apps');

		while ( e.childNodes.length > 0 )
		{
			e.removeChild(e.childNodes.item(0));
		}

		if ( !wappalyzer.isMobile )
		{
			// Clear tooltip
			var container = document.getElementById('wappalyzer-container');

			container.setAttribute('tooltiptext', wappalyzer.strings.getString('wappalyzer.title') + '\n---');

			// Disable and clear application statistics menu item
			e = document.getElementById('wappalyzer-app-stats');

			e.parentNode.setAttribute('disabled', true);

			while ( e.childNodes.length > 0 )
			{
				e.removeChild(e.childNodes.item(0));
			}
		}
	},

	showLabels: function(show)
	{
		e = document.getElementsByClassName('wappalyzer-app-name');

		for ( i = 0; i < e.length; i ++ )
		{
			e[i].style.display = show ? 'inline' : 'none';
		}
	},

	installSuccess: function()
	{
		wappalyzer.browser.removeEventListener('load', wappalyzer.installSuccess, false);

		wappalyzer.openTab(wappalyzer.homeUrl + 'install/success/');
	},

	openTab: function(url)
	{
		wappalyzer.browser.selectedTab = wappalyzer.browser.addTab(url);
	},

	bookmarklet: function()
	{
		if ( typeof(gBrowser) == 'undefined' && typeof(Browser) == 'undefined' )
		{
			wappalyzer.isBookmarklet = true;

			if ( !document.getElementById('wappalyzer-bookmarklet') )
			{
				var body = document.getElementsByTagName('body')[0];

				if ( body )
				{
					var container = document.createElement('div');

					container.innerHTML =
						'<div id="wappalyzer-bookmarklet" style="' +
						'	color: #332;' +
						'	font: 12px \'Trebuchet MS\';' +
						'	position: fixed;' +
						'	text-align: right;' +
						'	right: 2em;' +
						'	top: 2em;' +
						'	z-index: 9999999999;' +
						'	">' +
						'	<div id="wappalyzer-container" style="' +
						'		-moz-border-radius: 7px;' +
						'		-webkit-border-radius: 7px;' +
						'		background: #FAFAFA;' +
						'		border: 7px solid #332;' +
						'		margin-bottom: .3em;' +
						'		min-width: 15em;' +
						'		padding: 1em 2em;' +
						'		text-align: center;' +
						'		">' +
						'		<div style="' +
						'			border-bottom: 1px solid #332;' +
						'			font-size: 13px;' +
						'			padding-bottom: 1em;' +
						'			margin-bottom: 1em;' +
						'			"><strong>Wappalyzer</strong></div>' +
						'		<span id="wappalyzer-bookmarklet-apps"><em>No apps detected</em></span>' +
						'	</div>' +
						'	<span style="float: left;"><a href="http://wappalyzer.com" style="color: #332 !important;">home</a> | <a href="http://twitter.com/ElbertF" style="color: #332 !important;">follow me</a></span>' +
						'   <span style="float: right;">click to close</span>' +
						'</div>'
						;

					container.onclick = function() { body.removeChild(container); };

					body.appendChild(container);

					wappalyzer.analyzePage(
						document.location.href,
						document.documentElement.innerHTML,
						[],
						false
						);
				}
			}
		}
	}
};

wappalyzer.bookmarklet();