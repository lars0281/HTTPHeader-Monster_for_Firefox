
console.debug("start LinkLooker background");

let salt;

let db;

let indexedDB;

// databases:

// Apr 28 2021


/*
 * Apply rules to determine where link end up. Some links result in redirect,
 * but in the querystring there are values to indicate what the redirect URL
 * will be. Use rules to compute this URL without having to call the URL.
 *
 * Lookup link to check if ends in a redirect (use HTTP HEAD method)
 *
 * Apply controls to HTTP cookie
 *
 *
 * Control cookies
 *
 * Rules to which cookies to never send and allways send Rules scoped for
 * domain, fulldomain and URL
 *
 * Purpose to achieve with this functionality.
 *
 * 1) Always send the cookie to a server to avoid being confronted by
 * GPDR-mandated cookie acceptance form. Where these forms are prompted by a
 * missing cookie, clearing cookies will mean that the user is repeatedly asked
 * to accept cookies. Permanently setting the cookie will avoid this nuisance.
 *
 * Example www.youtube.com After the user click to connect to cookies, this is
 * returned to the browser set-cookie:
 * CONSENT=YES+cb.20210425-18-p0.en-GB+FX+944; Domain=.youtube.com; Expires=Sun,
 * 10-Jan-2038 07:59:59 GMT; Path=/; Secure; SameSite=none
 *
 * Send this cookie from then on: CONSENT=YES+cb.20210425-18-p0.en-GB+FX+944;
 * Note the seemingly random data after "YES". it contains a timestamp and some
 * other sender specific data. The rules must have a language to compute this
 * value as needed.
 *
 *
 * 2) Some services have a "first one is free" setup where the user is entitled
 * to see a limited number of something, but once the limit has been exceeded is
 * required to login
 *
 *
 *
 * Example www.nytimes.co m
 *
 *
 */

// context menu related


/*
 * to add context menu item for analysing links Added in v 1.0
 */

browser.contextMenus.create({
    id: "glovebox-link-reveal",
    title: "reveal the true endpoint of this link",
    contexts: ["link"]
});

// set up database connection

indexedDB = window.indexedDB || window.webkitIndexedDB ||
    window.mozIndexedDB || window.msIndexedDB;

// configuration of all indexed database instances
var index_db_config = [{
        dbname: "sourceHostnameRuleDB",
        objectstore: [{
                name: "sourceHostnameRuleStore",
                keyPath: "keyId",
                autoIncrement: false,
                index: [{
                        n: "keyId",
                        o: "keyId",
                        unique: "true"
                    }
                ]
            }
        ]
    }, {
        dbname: "sourceUrlRuleDB",
        objectstore: [{
                name: "sourceUrlRuleStore",
                keyPath: "keyId",
                autoIncrement: false,
                index: [{
                        n: "keyId",
                        o: "keyId",
                        unique: "true"
                    }
                ]
            }
        ]
    }, {
        dbname: "sourceDomainRuleDB",
        objectstore: [{
                name: "sourceDomainRuleStore",
                keyPath: "keyId",
                autoIncrement: false,
                index: [{
                        n: "keyId",
                        o: "keyId",
                        unique: "true"
                    }
                ]
            }
        ]
    }, {
        dbname: "destinationHostnameRuleDB",
        objectstore: [{
                name: "destinationHostnameRuleStore",
                keyPath: "keyId",
                autoIncrement: false,
                index: [{
                        n: "keyId",
                        o: "keyId",
                        unique: "true"
                    }
                ]
            }
        ]
    }, {
        dbname: "destinationUrlRuleDB",
        objectstore: [{
                name: "destinationUrlRuleStore",
                keyPath: "keyId",
                autoIncrement: false,
                index: [{
                        n: "keyId",
                        o: "keyId",
                        unique: "true"
                    }
                ]
            }
        ]
    }, {
        dbname: "destinationDomainRuleDB",
        objectstore: [{
                name: "destinationDomainRuleStore",
                keyPath: "keyId",
                autoIncrement: false,
                index: [{
                        n: "keyId",
                        o: "keyId",
                        unique: "true"
                    }
                ]
            }
        ]
    }
];

index_db_config2 = [{
    dbname: "sourceHostnameRuleDB",
    objectstore: [{
            name: "sourceHostnameRuleStore",
            keyPath: "keyId",
            autoIncrement: false,
            index: [{
                    n: "keyId",
                    o: "keyId",
                    unique: "true"
                }
            ]
        }
    ]
}];

// all default rules/policies
var default_policies = [{
        dbname: 'sourceHostnameRuleDB',
        dbstore: 'sourceHostnameRuleStore',
        keyPath: 'keyId',
        policy: {
            keyId: 'https://www.google.com/',
            sourceHostname: 'https://www.google.com/',
            url_match: 'https://www.google.com/',
            scope: 'Hostname',
            direction: 'source',
            steps: [{
                    procedure: "qs_param",
                    parameters: [{
                            value: "url",
                            notes: "read url from querystring"
                        }
                    ],
                    notes: "grab the url parameter from the querystring"
                }, {
                    procedure: "uri_decode",
                    parameters: [],
                    notes: "uri decode"
                }
            ],
            notes: '',
            createtime: '202001010001'
        }
    }, {
        dbname: 'sourceHostnameRuleDB',
        dbstore: 'sourceHostnameRuleStore',
        keyPath: 'keyId',
        policy: {
            keyId: 'https://www.facebook.com/',
            sourceHostname: 'https://www.facebook.com/',
            url_match: 'https://www.facebook.com/',
            scope: 'Domain',
            direction: 'source',
            steps: [{
                    procedure: "regexp",
                    parameters: [{
                            value: "sDfbclid=[^&]*DDg",
                            notes: "remove fbclid from qs"
                        }
                    ],
                    notes: "edit querystring"
                }
            ],
            notes: 'remove tracking id from urls to thrrd parties',
            createtime: '202001010001'
        }
    }, {
        dbname: 'sourceDomainRuleDB',
        dbstore: 'sourceDomainRuleStore',
        keyPath: 'keyId',
        policy: {
            keyId: 'google.com',
            sourceDomain: 'google.com',
            url_match: 'google.com',
            scope: 'Domain',
            direction: 'source',
            steps: [{
                    procedure: "regexp",
                    parameters: [{
                            value: "sDfbclid=[^&]*DDg",
                            notes: "remove fbclid from qs"
                        }
                    ],
                    notes: "edit querystring"
                }
            ],
            notes: 'remove tracking id from urls to thrrd parties',
            createtime: '202001010001'
        }
    }, {
        dbname: 'sourceDomainRuleDB',
        dbstore: 'sourceDomainRuleStore',
        keyPath: 'keyId',
        policy: {
            keyId: 'facebook.com',
            sourceDomain: 'facebook.com',
            url_match: 'facebook.com',
            scope: 'Domain',
            direction: 'source',
            steps: [{
                    procedure: "regexp",
                    parameters: [{
                            value: "sDfbclid=[^&]*DDg",
                            notes: "remove fbclid from qs"
                        }
                    ],
                    notes: "tracking token from querystring"
                }, {
                    procedure: "regexp",
                    parameters: [{
                            value: "s/(utm|hsa)_[a-z]*=[^&]*//g",
                            notes: "delete parameters with names starting with utm_ and hsa_"
                        }
                    ],
                    notes: "remove suspicious parameters from querystring"
                }
            ],
            notes: 'remove tracking id from urls to thrrd parties',
            createtime: '202001010001'
        }
    }, {
        dbname: 'sourceHostnameRuleDB',
        dbstore: 'sourceHostnameRuleStore',
        keyPath: 'keyId',
        policy: {
            keyId: 'https://www.imdb.com/',
            sourceHostname: 'https://www.imdb.com/',
            url_match: 'https://www.imdb.com/',
            scope: 'Hostname',
            direction: 'source',
            steps: [{
                    procedure: "regexp",
                    parameters: [{
                            value: "sDcharDCHARDg",
                            notes: "test"
                        }
                    ],
                    notes: "test"
                }
            ],
            notes: 'test',
            createtime: '202001010001'
        }
    }, {
        dbname: 'sourceHostnameRuleDB',
        dbstore: 'sourceHostnameRuleStore',
        keyPath: 'keyId',
        policy: {
            keyId: 'https://www.linkedin.com/',
            sourceHostname: 'https://www.linkedin.com/',
            url_match: 'https://www.linkedin.com/',
            scope: 'Hostname',
            direction: 'source',
            steps: [{
                    procedure: "regexp",
                    parameters: [{
                            value: "s/(utm|hsa)_[a-z]*=[^&]*//g",
                            notes: "delete parameters with names starting with utm_ and hsa_"
                        }
                    ],
                    notes: "remove suspicious parameters from querystring"
                }, {
                    procedure: "regexp",
                    parameters: [{
                            value: "s/[&]*li_fat_id=[^&]*//g",
                            notes: "delete qs parameter with named li_fat_id"
                        }
                    ],
                    notes: "remove extraneous parameter from querystring"
                }
            ],
            notes: 'test',
            createtime: '202001010001'
        }
    }, {
        dbname: 'destinationDomainRuleDB',
        dbstore: 'destinationDomainRuleStore',
        keyPath: 'keyId',
        policy: {
            keyId: 'ct.sendgrid.net',
            destinationDomain: 'ct.sendgrid.net',
            url_match: 'ct.sendgrid.net',
            scope: 'Domain',
            direction: 'destination',
            steps: [{
                    procedure: "regexp",
                    parameters: [{
                            value: "sD-D%Dg",
                            notes: "test"
                        }
                    ],
                    notes: "test"
                }
            ],
            notes: 'test',
            createtime: '202001010001'
        }
    }, {
        dbname: 'destinationHostnameRuleDB',
        dbstore: 'destinationHostnameRuleStore',
        keyPath: 'keyId',
        policy: {
            keyId: 'https://www.facebook.com/',
            destinationHostname: 'https://www.facebook.com/',
            url_match: 'https://www.facebook.com/',
            scope: 'Hostname',
            direction: 'destination',
            steps: [{
                    procedure: "regexp",
                    parameters: [{
                            value: "sD\\?.*DDg",
                            notes: "test"
                        }
                    ],
                    notes: "test"
                }
            ],
            notes: 'test',
            createtime: '202001010001'
        }
    }, {
        dbname: 'destinationHostnameRuleDB',
        dbstore: 'destinationHostnameRuleStore',
        keyPath: 'keyId',
        policy: {
            keyId: 'http://ad.doubleclick.net/',
            destinationHostname: 'http://ad.doubleclick.net/',
            url_match: 'http://ad.doubleclick.net/',
            scope: 'Hostname',
            direction: 'destination',
            steps: [{
                    procedure: "regexp",
                    parameters: [{
                            value: "sD.*(http[s]*://[^&]*).*D$1Dg",
                            notes: "test"
                        }
                    ],
                    notes: "test"
                }, {
                    procedure: "regexp",
                    parameters: [{
                            value: "sD\\?.*DDg",
                            notes: "test"
                        }
                    ],
                    notes: "test"
                }
            ],
            notes: 'test',
            createtime: '202001010001'
        }
    }, {
        dbname: 'destinationHostnameRuleDB',
        dbstore: 'destinationHostnameRuleStore',
        kayPath: 'keyId',
        policy: {
            keyId: 'https://www.linkedin.com/',
            destinationHostname: 'https://www.linkedin.com/',
            url_match: 'https://www.linkedin.com/',
            scope: 'Hostname',
            direction: 'destination',
            steps: [{
                    procedure: "regexp",
                    parameters: [{
                            value: "s/trackingId=[^&]*//g",
                            notes: "delete trackingId from querystring"
                        }
                    ],
                    notes: "remove tracking token from querystring used inside the linkedin application"
                }
            ],
            notes: 'remove tracker',
            createtime: '202001010001'
        }
    }, {
        dbname: 'destinationHostnameRuleDB',
        dbstore: 'destinationHostnameRuleStore',
        keyPath: 'keyId',
        policy: {
            keyId: 'https://ad.doubleclick.net',
            destinationHostname: 'https://ad.doubleclick.net',
            url_match: 'https://ad.doubleclick.net',
            scope: 'Hostname',
            direction: 'destination',
            destinationHostname: 'https://ad.doubleclick.net',
            steps: [{
                    procedure: "regexp",
                    parameters: [{
                            value: "sD\\?.*DDg",
                            notes: "remove the querystring"
                        }
                    ],
                    notes: "reduce to ;dc_trk_aid=11111111;dc_trk_cid=000000"
                }, {
                    procedure: "regexp",
                    parameters: [{
                            value: "sD\\?.*DDg",
                            notes: "remove semmi-colon separated parameters from path where no value has been set ;dc_rdid=  "
                        }
                    ],
                    notes: "reduce to ;dc_trk_aid=11111111;dc_trk_cid=000000"
                }
            ],
            notes: 'test',
            createtime: '202001010001'
        }
    }, {
        dbname: 'destinationUrlRuleDB',
        dbstore: 'destinationUrlRuleStore',
        keyPath: 'keyId',
        policy: {
            keyId: 'https://l.facebook.com/l.php',
            destinationUrl: 'https://l.facebook.com/l.php',
            url_match: 'https://l.facebook.com/l.php',
            scope: 'Url',
            direction: 'destination',
            steps: [{
                    procedure: "qs_param",
                    parameters: [{
                            value: "u",
                            notes: "read u from querystring"
                        }
                    ],
                    notes: "grab the u parameter from the querystring"
                }, {
                    procedure: "uri_decode",
                    parameters: [{
                            value: "N/A",
                            notes: ""
                        }
                    ],
                    notes: "uri decode"
                }
            ],
            notes: '',
            createtime: '202001010001'
        }
    }, {
        dbname: 'destinationUrlRuleDB',
        dbstore: 'destinationUrlRuleStore',
        keyPath: 'keyId',
        policy: {
            keyId: 'https://www.google.com/url',
            destinationUrl: 'https://www.google.com/url',
            url_match: 'https://www.google.com/url',
            scope: 'Url',
            direction: 'destination',
            steps: [{
                    procedure: "qs_param",
                    parameters: [{
                            value: "url",
                            notes: "read url from querystring"
                        }
                    ],
                    notes: "grab the url parameter from the querystring"
                }, {
                    procedure: "uri_decode",
                    parameters: [{
                            value: "N/A",
                            notes: ""
                        }
                    ],
                    notes: "uri decode"
                }
            ],
            notes: '',
            createtime: '202001010001'
        }
    }, {
        dbname: 'destinationUrlRuleDB',
        dbstore: 'destinationUrlRuleStore',
        keyPath: 'keyId',
        policy: {
            keyId: 'https://ideas-admin.lego.com/mailing/email_link',
            destinationUrl: 'https://ideas-admin.lego.com/mailing/email_link',
            url_match: 'https://ideas-admin.lego.com/mailing/email_link',
            scope: 'Url',
            direction: 'destination',
            steps: [{
                    procedure: "qs_param",
                    parameters: [{
                            value: "payLoad",
                            notes: "read payLoad from querystring"
                        }
                    ],
                    notes: "grab the payLoad parameter from the querystring"
                }, {
                    procedure: "uri_decode",
                    parameters: [{
                            value: "N/A",
                            notes: ""
                        }
                    ],
                    notes: "uri decode"
                }, {
                    procedure: "base64_decode",
                    parameters: [{
                            value: "N/A",
                            notes: ""
                        }
                    ],
                    notes: "BASE64 decode"
                }, {
                    procedure: "JSON_path",
                    parameters: [{
                            value: "url",
                            notes: "read url from object"
                        }
                    ],
                    notes: "get piece of JSON object"
                }
            ],
            notes: 'handle links embedded in emails from LEGO',
            createtime: '202001010001'
        }
    }, {
        dbname: 'destinationUrlRuleDB',
        dbstore: 'destinationUrlRuleStore',
        keyPath: 'keyId',
        policy: {
            keyId: 'https://dagsavisen.us11.list-manage.com/track/click',
            destinationUrl: 'https://dagsavisen.us11.list-manage.com/track/click',
            url_match: 'https://dagsavisen.us11.list-manage.com/track/click',
            scope: 'Url',
            direction: 'destination',
            steps: [{
                    procedure: "replace_with",
                    parameters: [{
                            value: "http://www.dagsavisen.no/minside",
                            notes: "replace"
                        }, {
                            value: "http://www.dagsavisen.no/minside2",
                            notes: "replace2 "
                        }, {
                            value: "http://www.dagsavisen.no/minside3",
                            notes: "replace 3"
                        }
                    ],
                    notes: "replace with http://www.dagsavisen.no/minside"
                }
            ],
            notes: 'test',
            createtime: '202001010001'
        }
    }, {
        dbname: 'destinationUrlRuleDB',
        dbstore: 'destinationUrlRuleStore',
        keyPath: 'keyId',
        policy: {
            keyId: 'https://www.youtube.com/watch',
            destinationUrl: 'https://www.youtube.com/watch',
            url_match: 'https://www.youtube.com/watch',
            scope: 'Url',
            direction: 'destination',
            steps: [{
                    procedure: "regexp",
                    parameters: [{
                            value: "sD(\\?v=[^&]*).*D$1Dg",
                            notes: "sed statement to remove all but the v parameter"
                        }
                    ],
                    notes: "youtube videos should be short, leave only v parameter in query string"
                }
            ],
            notes: 'clean youtube URLs',
            createtime: '202001010001'
        }
    }, {
        dbname: 'destinationUrlRuleDB',
        dbstore: 'destinationUrlRuleStore',
        keyPath: 'keyId',
        policy: {
            keyId: 'https://www.flysas.com/en/flexible-booking/',
            destinationUrl: 'https://www.flysas.com/en/flexible-booking/',
            url_match: 'https://www.flysas.com/en/flexible-booking/',
            scope: 'Url',
            direction: 'destination',
            steps: [{
                    procedure: "regexp",
                    parameters: [{
                            value: "s/eCodsId=[^&]*//g",
                            notes: "sed-type regexp statement to delete CodsId from url"
                        }
                    ],
                    notes: "remove piece of querystring"
                }
            ],
            notes: 'SAS tracing offers',
            createtime: '202001010001'
        }
    }

];


var default_policies2 = [{
    dbname: 'sourceHostnameRuleDB',
    dbstore: 'sourceHostnameRuleStore',
    keyPath: 'keyId',
    policy: {
        keyId: 'https://www.google.com/',
        sourceHostname: 'https://www.google.com/',
        url_match: 'https://www.google.com/',
        scope: 'Hostname',
        direction: 'source',
        steps: [{
                procedure: "qs_param",
                parameters: [{
                        value: "url",
                        notes: "read url from querystring"
                    }
                ],
                notes: "grab the url parameter from the querystring"
            }, {
                procedure: "uri_decode",
                parameters: [],
                notes: "uri decode"
            }
        ],
        notes: '',
        createtime: '202001010001'
    }
}];

//maintain current policies in hash tables to keep the data "in-memory"


var in_memory_policies = {};

in_memory_policies["sourceUrlRuleDB"] = {};
in_memory_policies["sourceDomainRuleDB"] = {};
in_memory_policies["sourceHostnameRuleDB"] = {};
in_memory_policies["destinationUrlRuleDB"] = {};
in_memory_policies["destinationDomainRuleDB"] = {};
in_memory_policies["destinationHostnameRuleDB"] = {};

try {
    //Set required indexeddb database and add default items in those databases.
    indexeddb_setup_async(indexedDB).then(function (res) {
        console.debug(res);
        
        return  indexeddb_setup_async(indexedDB);

    }).then(function () {
        console.debug("complete");
        return  indexeddb_setup_async(indexedDB);

    }).then(function () {
        console.debug("complete");
        
        return setup_default_policies_async();

    }).then(function () {
        console.debug("complete");

        return refresh_inmemory_policy_datastore_async("sourceUrlRuleDB", "sourceUrlRuleStore","keyId");
    }).then(function () {

        return refresh_inmemory_policy_datastore_async("sourceDomainRuleDB", "sourceDomainRuleStore","keyId");
    }).then(function () {
        return refresh_inmemory_policy_datastore_async("sourceHostnameRuleDB", "sourceHostnameRuleStore","keyId");
    }).then(function () {

        return refresh_inmemory_policy_datastore_async("destinationUrlRuleDB", "destinationUrlRuleStore","keyId");
    }).then(function () {

        return refresh_inmemory_policy_datastore_async("destinationDomainRuleDB", "destinationDomainRuleStore","keyId");
    }).then(function () {
        return refresh_inmemory_policy_datastore_async("destinationHostnameRuleDB", "destinationHostnameRuleStore","keyId");

    }).then(function () {}).then(function () {
        console.debug("in-memory databases refreshed");
        console.debug(JSON.stringify(in_memory_policies));

    }).catch(function (err) {
        console.debug(err);
    });

} catch (e) {
    console.debug(e);
}

// listener for message sent from the admin page of the plugin
browser.runtime.onMessage.addListener(function (message, sender, sendResponse) {
    console.debug("message:" + JSON.stringify(message));
    console.debug("sender:" + JSON.stringify(sender));
    console.debug("sendResponse:" + sendResponse);

    console.debug("received from page:  message: " + JSON.stringify(message) + " message.type=" + message.type);

    console.debug("request:" + message[0]);
    console.debug("request:" + message.request);

    console.debug("request:" + JSON.stringify(message.request));
    console.debug("request:" + JSON.stringify(message.request.sendRule));

    console.debug("request:" + message.request.sendRule);

    console.debug("request:" + message.linkurl);

    try {

        if (message.request.sendRule == 'toEditPopup') {
            console.debug("contact edit popup:");

            var page_message = message.message;
            console.debug("page_message:" + page_message);
            // Simple example: Get data from extension's local storage
            // var result = localStorage.getItem('whatever');


            var result = JSON.parse('{"test":"one"}');
            // Reply result to content script
            sendResponse(result);
        }

    } catch (e) {
        console.debug(e);
    }

    try {

        // make call to rule editing popup containing the rule to display in it.


        if (message && message.type == 'page') {
            console.debug("page_message:");
            var page_message = message.message;
            console.debug("page_message:" + page_message);
            // Simple example: Get data from extension's local storage
            // var result = localStorage.getItem('whatever');
            var result = JSON.parse('{"test":"one"}');
            // Reply result to content script
            sendResponse(result);
        }

        if (message && message.request == 'skinny_lookup' && message.linkurl != '') {
            console.debug("look up :" + message.linkurl);
            var true_destination_url = "";
            true_destination_url = skinny_lookup(message.linkurl);
            sendResponse({
                true_destination_url: true_destination_url,
                linkUrl: message.linkurl,
                success: "true"
            });
        }
    } catch (e) {
        console.debug(e);
    }

});

if (!window.indexedDB) {
    console.debug("Your browser doesn't support a stable version of IndexedDB. Such and such feature will not be available.");
} else {
    console.debug("1.1.0");
}

let pendingCollectedUrls = [];

browser.contextMenus.onClicked.addListener((info, tab) => {
    console.debug("background.js: browser.contextMenus.onClicked.addListener");
    console.debug("background.js: browser.contextMenus.onClicked.addListener:info:" + JSON.stringify(info));
    console.debug("background.js: browser.contextMenus.onClicked.addListener:tab:" + JSON.stringify(tab));

    /*
     * When the user has selected from the context meny to revel the true end
     * point of a url
     *
     */
    if (info.menuItemId == "glovebox-link-reveal") {
        console.debug("glovebox-link-reveal");
        // console.debug(info);
        // console.debug(tab);
        reveal_true_url_endpoint(info, tab);

    } else if (info.menuItemId == "selected-text-lookup") {
        console.debug("selected-text-lookup");
        // console.debug(info);
        // console.debug(tab);
        selected_text_lookup(info, tab);

    }

    console.debug("#### request completed");
});

// add listener to open the admin page when user clicks on the icon in the
// toolbar
browser.browserAction.onClicked.addListener(() => {
    // use this functionality to get a full tabpage
    browser.tabs.create({
        url: "/rule-admin.html"
    });
    // Can replace the above with a direct referal to the html, in the manifest.
    // - but this would not provide a full tab-page
    // "brower_action": {
    // "default_popup": "navigate-collection.html"

});

function indexeddb_setup_async(indexedDB) {

    return new Promise(
        function (resolve, reject) {

        try {
            var p = [];

            for (var i = 0; i < index_db_config.length; i++) {

                p.push(create_indexeddb_async(indexedDB, index_db_config[i]));
                console.debug("1.1.1");
            }
            console.debug("1.1.2");
            // Using .catch:
            Promise.all(p)
            .then(values => {
                console.debug("1.1.3");

                console.debug(values);
                resolve(values);
                console.debug("1.1.3.1");

            })
            .catch(error => {
                console.debug("1.1.4");

                console.error(error.message);
                resolve(null);
                console.debug("1.1.4.1");
            });
        } catch (f) {
            console.debug("1.1.5");

            console.error(f);
            resolve(null);
            console.debug("1.1.5.1");
        }
        console.debug("1.1.6");

    });
    console.debug("1.1.7");

}

function refresh_inmemory_policy_datastore_async(dbname, dbstorename,keyPath) {
    // read out all policies from the policy database and compare the current in-memory has arrays with the just-read data.
    // Add what is missing and remove the surplus.
    return new Promise(
        function (resolve, reject) {
     //   console.debug("#####################################" + dbname);
     //   console.debug("#####################################" + dbstorename);
      //  console.debug("#####################################" + keyPath);

        try{
        dump_db_2_hash_async(dbname, dbstorename).then(function (res) {
            one = res;
            console.debug(JSON.stringify(one));

            // loop through all returned objects and insert them in the hash array
            console.debug(one.length);
            if (one.length > 0){
            console.debug(one[0]);
            console.debug(one[0][keyPath]);
            for (var i = 0; i < one.length; i++) {
                // copy over the whole object, change this later
                //ourceHostnamePolicyDB_inmemory[one[i].keyId] = one[i];
                in_memory_policies[dbname][one[i][keyPath]] = one[i];
            }
            }
            // add functionality for removing any entries no longer present in the database
            resolve(true);
        });
        } catch (e) {
            console.debug(e);
        }
        
    });
}

function dump_db_2_hash_async(dbName, storeName3) {

    return new Promise(
        function (resolve, reject) {
        // access database
        console.debug("-------------------------------------");

        console.debug("dump_db access database: " + dbName);
        var dbRequest = indexedDB.open(dbName);

        //     try {
        dbRequest.onsuccess = function (event3) {
            var database3 = event3.target.result;

            //console.debug("access datastore: " + storeName3);

            var transaction3 = database3.transaction([storeName3]);
            var objectStore3 = transaction3.objectStore(storeName3);

            var allRecords3 = objectStore3.getAll();
            allRecords3.onsuccess = function () {
                console.debug("-------------------------------------");
                console.debug("-------------------------------------");

                const res3 = allRecords3.result;
                console.debug(res3);
                console.debug("## results" + JSON.stringify(res3));
                //listOfKeys = listOfKeys + ',"privateKeys":' + JSON.stringify(res3) + '';
                console.debug("-------------------------------------");
                console.debug("-------------------------------------");

                // get private(and their public component) signing keys
                database3.close();
                resolve(res3);

            };
            database3.close();

        }
        //            dbRequest.close();
        //      } catch (e) {
        //         console.debug(e);
        //         resolve("error");
        //    }
    });
}

/*
 * Crate an instance IndexedDB
 * Takes a JSON structure specifying the configuration
 *
 * {
dbname: "sourceUrlRuleDB",
objectstore: [{
name: "sourceUrlRuleStore",
keyPath: "keyId",
autoIncrement: false,
index: [{
n: "keyId",
o: "keyId",
unique: "true"
}
]
}
]
}




/*
 * Crate an instance IndexedDB
 * Takes a JSON structure specifying the configuration
 *
 * {
dbname: "sourceUrlRuleDB",
objectstore: [{
name: "sourceUrlRuleStore",
keyPath: "keyId",
autoIncrement: false,
index: [{
n: "keyId",
o: "keyId",
unique: "true"
}
]
}
]
}
 *
 * */


function create_indexeddb_async(indexedDB, dbconfig) {

    console.debug("# create_indexeddb_async: " + JSON.stringify(dbconfig));

    // To do: add logic so as not to try to create tables already present


    return new Promise(
        function (resolve, reject) {

        console.debug("database config: " + JSON.stringify(dbconfig));
       // console.debug("database name: " + dbconfig.dbname);
       // console.debug("objectstore name: " + dbconfig.objectstore[0].name);
       // console.debug("key: " + dbconfig.objectstore[0].keyPath);
       // console.debug("index: " + JSON.stringify(dbconfig.objectstore[0].index[0].unique));

        let db;

        // ########
        var request7 = indexedDB.open(dbconfig.dbname, 1);
        request7.onupgradeneeded = function (event5) {
            db = event5.target.result;
            db.onerror = function (event4) {};
            // Create an objectStore in this database to keep offers to passout decryption keys in a secure way.
            console.debug("create objectstore " + dbconfig.objectstore[0].name + " in " + dbconfig.dbname + " for secure key offers");
            var objectStore = db.createObjectStore(dbconfig.objectstore[0].name, {
                    keyPath: dbconfig.objectstore[0].keyPath
                });

            console.debug("db create objectstore index " + dbconfig.objectstore[0].index[0].n);

            objectStore.createIndex(dbconfig.objectstore[0].index[0].n, dbconfig.objectstore[0].index[0].o, {
                unique: dbconfig.objectstore[0].index[0].unique
            });
            console.debug("completed");
            resolve(true);
        };
        request7.onerror = function (event1) {
            console.debug("dp open request error 201");
        };
        request7.onsuccess = function (event) {
            console.debug("db open success");
            var db_1 = event.target.result;
            console.debug(db_1);
            db_1.onerror = function (event2) {
                console.debug("db open request error 2");

                console.debug("db create objectstore");

                var objectStore = db_1.createObjectStore(dbconfig.objectstore[0].name, {
                        keyPath: dbconfig.objectstore[0].keyPath
                    });

                console.debug("db create objectstore index " + dbconfig.objectstore[0].index[0].n);

                objectStore.createIndex(dbconfig.objectstore[0].index[0].n, dbconfig.objectstore[0].index[0].o, {
                    unique: dbconfig.objectstore[0].index[0].unique
                });
                console.debug("completed");
                resolve(true);
            };
            db_1.onsuccess = function (event3) {
                console.debug("db open request success 2");
                var objectStore = db_1.createObjectStore(dbconfig.objectstore[0].name, {
                        keyPath: dbconfig.objectstore[0].keyPath
                    });

                console.debug("db create objectstore index " + dbconfig.objectstore[0].index[0].n);

                objectStore.createIndex(dbconfig.objectstore[0].index[0].n, dbconfig.objectstore[0].index[0].o, {
                    unique: dbconfig.objectstore[0].index[0].unique
                });
                console.debug("completed");
                resolve(true);
            };
            console.debug("completed");
            resolve(true);
        };

    });

}



function create_indexeddb_async_test(indexedDB, dbconfig) {

    console.debug("database config: " + JSON.stringify(dbconfig));

    // To do: add logic so as not to try to create tables already present

    try {

        return new Promise(
            function (resolve, reject) {

            console.debug("indexedDB: " + indexedDB);
            console.debug("database config: " + JSON.stringify(dbconfig));
            console.debug("database name: " + dbconfig.dbname);
            console.debug("objectstore name: " + dbconfig.objectstore[0].name);
            console.debug("key: " + dbconfig.objectstore[0].keyPath);
            console.debug("index: " + JSON.stringify(dbconfig.objectstore[0].index[0].unique));

            // create connection to the database, and create the database if it is not there. 
            databaseCreateConnect_async(dbconfig.dbname).then(function(db){
            console.debug(db);
            var ds;
            	if (typeof db !== "unknown") {
            		   console.debug(db);
            	            		return  datastoreCreateConnect_async(db, dbconfig.objectstore[0].name,dbconfig.objectstore[0].keyPath);
            	}else{
            		   console.debug(db);
            	         
            		return datastoreCreateConnect_async(db, dbconfig.objectstore[0].name,dbconfig.objectstore[0].keyPath);
            		
            		
            	}
            
            }).then(function(ds){
            	console.debug(ds);
        		
            	
            });

        });
    } catch (e) {
        console.debug(e);
    }
}

function databaseExists(dbname, callback) {
    var req = indexedDB.open(dbname);
    var existed = true;
    req.onsuccess = function () {
        req.result.close();
        if (!existed)
            indexedDB.deleteDatabase(dbname);
        callback(existed);
    }
    req.onupgradeneeded = function () {
        existed = false;
    }
}


// return connection to a database, create it if needed
function databaseCreateConnect_async(dbname) {
    console.debug("databaseCreateConnect(+dbname + )");
    try{
        return new Promise(
                function (resolve, reject) {
    let db;
    var request7 = indexedDB.open(dbname, 1);
    request7.onupgradeneeded = function (event5) {
        db = event5.target.result;
        db.onerror = function (event4) {console.error(event4)};
        console.debug(db);
        resolve( db);
    };
    request7.onerror = function (event1) {
        console.debug("dp open request error 201");
    };
    request7.onsuccess = function (event) {
        console.debug("db open success");
        var db_1 = event.target.result;
        console.debug(db_1);
        resolve (db_1);
    }
                });
        
    } catch (e) {
        console.debug(e);
    }
}


//return connection to a datastore inside a database, and create it if needed
// return a handler
function datastoreCreateConnect_async(database, storeName, keyPath) {
 console.debug("datastoreCreateConnect(+storeName + )");
try{
    return new Promise(
            function (resolve, reject) {
            	try {
 var transaction = database.transaction([storeName]);
            	} catch (e) {
            	    console.debug(e);
            	    // create datastore
            	    var objectStore = database.createObjectStore(storeName, {
                        keyPath: keyPath
                    });
            	    console.debug(objectStore);
            	    
            	}
  console.debug("loadFromIndexedDB:transaction: " +  JSON.stringify(transaction));
 var objectStore = transaction.objectStore(storeName);
 
 console.debug("loadFromIndexedDB:objectStore: " +  JSON.stringify(objectStore));
 
 resolve(objectStore);
 
            });
} catch (e) {
    console.debug(e);
}
}



function databaseExists_async(dbname) {
    console.debug("databaseExists_async");
    return new Promise(
        function (resolve, reject) {
        var dbRequest = indexedDB.open(dbname);
console.debug(dbRequest);        
        var existed = true;
        dbRequest.onsuccess = function () {
        	console.debug("success");
        	dbRequest.result.close();
           // if (!existed) {
           //     indexedDB.deleteDatabase(dbname);
              resolve(true);
           // }
        }
        dbRequest.onupgradeneeded = function () {
            existed = false;
            resolve(false);

        }
    });
}


function datastoreExists_async(dbName,storeName) {
    console.debug("## datastoreExists_async");
    try {
    	return new Promise(
        function (resolve, reject) {
        	  var dbRequest = indexedDB.open(dbName);

               dbRequest.onerror = function (event) {
                   reject(Error("Error text"));
               };

               dbRequest.onupgradeneeded = function (event) {
                   // Objectstore does not exist. Nothing to load
                   event.target.transaction.abort();
                   reject(Error('Not found'));
               };

               dbRequest.onsuccess = function (event) {
                   // console.debug("loadFromIndexedDB:onsuccess ");

            	   try{
                   var database = event.target.result;
                   var transaction = database.transaction([storeName]);
                    console.debug("loadFromIndexedDB:transaction: " + JSON.stringify(transaction));
                   var objectStore = transaction.objectStore(storeName);
                   console.debug("loadFromIndexedDB:objectStore: " + JSON.stringify(storeName));
                   
                   
               } catch (e) {
            	    console.debug(e);
            	    resolve(false);
            	}
                   
                   };
                   

    });
} catch (e) {
    console.debug(e);
}
}

function skinny_lookup(url, info) {
    console.debug("#start: skinny_lookup: " + url);
    var true_destination_url = "";
    var xhr = new XMLHttpRequest();
    // mark "false" to indicate synchronous
    try {
        xhr.open('HEAD', url, false);
        // request plain text return to look for http-based redirects too
        // xhr.responseType = 'blob';
    } catch (e) {
        console.debug(e);
    }
    try {
        xhr.onload = function () {
            console.debug(xhr);

            // check for a Location HTTP header in the response
            console.debug(xhr);
            true_destination_url = xhr.responseURL;
        };
    } catch (e) {
        console.debug(e);
    }
    xhr.onerror = () => console.debug(xhr.statusText);
    try {

        xhr.send();
    } catch (e) {
        // console.debug(xhr);
        console.debug(e);
    }

    try {

        return true_destination_url;
    } catch (e) {
        // console.debug(xhr);
        console.debug(e);
    }
}

/*
 *
 */

function selected_text_lookup(info, tab) {
    console.debug("#start: selected_text_lookup");
    console.debug(info);
    console.debug(tab);
}

// receive notice when user rightclick on a link and selects "reveal the true
// endpoint of URL"

// make call back to page script to run additonal code


function reveal_true_url_endpoint(info, tab) {
    // console.debug("#start: reveal_true_url_endpoint");
    // console.debug(info);
    // console.debug(tab);

    // console.debug("###calling ");
    // console.debug(destination_url_rules);

    // information on which link was selected, use this to correctly
    // identify it in the content script.

    var tabId = tab.id;
    var frameId = info.frameId;
    var targetElementId = info.targetElementId;

    var linkUrl = info.linkUrl;
    var linkText = info.linkText;

    // console.debug("urlendpoint: " + info.linkUrl);
    // console.debug("tabId: " + tabId);

    console.debug("location page: " + info.pageUrl);

    var true_destination_url = "";

    // Setup a ruleset. With some default values ( and later the opportunity for user to
    // configure automatic behaviour.)


    var new_url = info.linkUrl;

    // if the Pagelink-Sanitizer is running, links may have "disable" prepended to the protocol, if so, remove it here.

    var is_blocked = new RegExp("^disable[d]*http[s]*:/[\/]*", 'i');
    if (is_blocked.test(new_url)) {
        // ok, remove the "disabled" part

        new_url = new_url.replace(/^disable[d]*h/i, "h");

    }

    // apply rules to generate new URL. The rules are a collection of
    // rewrite statements applied to the submitted URL.
    // The rules are scoped in two ways: by source/destination and complete
    // URL (protocol fully-qualified domain port path), full domain
    // (protocol fully-qualified domain port ) and domain ( domain port )
    // The rewrite rules are applied in sequentially.

    // The source rules (if any) are applied first.

    // Then the destination rules are applied. And on top of any changes
    // made previosuly.

    // Two URLs are submitted: the URL of the page where the link is found,
    // and the link itself.


    // new_url = "";
    rules_enforcement_async(info.pageUrl, new_url).then(function (re) {
        // console.debug("#### " + re);

        new_url = re;

        console.debug("#### after first rewrite: " + new_url);
        // if the rules caused the URL to be changed, there might also be rules
        // governing the new URL, so run through it again.

        return rules_enforcement_async(info.pageUrl, new_url);
    }).then(function (re) {
        new_url = re;
        console.debug("#### after second rewrite: " + new_url);

        // new_url = rules_enforcement(info.pageUrl ,new_url);
        // console.debug("#### " + new_url);

        // Call the URL by default if not rules applies to the URL.
        // If the URL has not been changed, assume no rule pertained to it, so
        // look it up directly.


        // console.debug("true_destination_url: " + true_destination_url );


        // check linkURL against URL


        // send message back to the content script with this info

        return getRedirectUrl(new_url);

    }).then(function (url) {

        if (url == "not_found") {
            console.debug("#call back to content script");
            // query for the one active tab


            browser.tabs.executeScript(tabId, {
                file: "content_scripts/RevealUrl.js",
                frameId: frameId

            }).then(function (result) {

                // query for the one active tab
                return browser.tabs.query({
                    active: true,
                    currentWindow: true
                });

            }).then(function (tabs) {
                // send message back to the active tab
                console.debug("#call back to content script in tab:" + tabs[0].id);
                return browser.tabs.sendMessage(tabs[0].id, {
                    targetElementId: targetElementId,
                    true_destination_url: "not_found",
                    linkText: linkText,
                    linkUrl: linkUrl,
                    success: "true"
                });
            });

        } else {

            // verify that the URL satify the minimum requirements
            var url_wellformed_regexp = /.*/i;

            // console.debug(url_wellformed_regexp);
            // console.debug("url_wellformed_regexp.text("+url+"): " +
            // url_wellformed_regexp.test(url));
            if (url.length > 9 && url_wellformed_regexp.test(url)) {
                true_destination_url = url;
            } else {
                true_destination_url = new_url;
            }

            // make attempt to clean the URL returned. In case of URL shorteners,
            // any manner of "villany" may be lurking

            rules_enforcement_async(info.pageUrl, true_destination_url).then(function (res) {
                console.debug(res);
                true_destination_url = res;

                //return browser.tabs.executeScript(tabId, {
                //    file: "content_scripts/RevealUrl.js",
                //    frameId: frameId
                //});

                //        }).then(function (result) {

                // query for the one active tab
                return browser.tabs.query({
                    active: true,
                    currentWindow: true
                });

            }).then(function (tabs) {

                // send message back to the active tab
                console.debug("#call back to content script tab:" + tabs);
                return browser.tabs.sendMessage(tabs[0].id, {
                    targetElementId: targetElementId,
                    true_destination_url: true_destination_url,
                    linkText: linkText,
                    linkUrl: linkUrl,
                    success: "true"
                });
                // }).then(function (res) {
                // console.debug("###### getHTML response " + JSON.stringify(res));
                // glovebox_token_ciphertext = res.response.token;

            });

        }

    });

}

function getRedirectUrlUsingHTTPGET_async(url) {
    // console.debug("##### getRedirectUrl.start: " + url);
    try {
        var p = new Promise((resolve, reject) => {
                const xhr = new XMLHttpRequest();
                xhr.open('HEAD', url, true);
                xhr.responseType = 'blob';
                xhr.onload = function () {
                    // resolve(xhr.response);
                    var reader = new FileReader();
                    console.debug(xhr.response);
                    console.debug(xhr);

                    var http_status_code = xhr.status;

                    console.debug(xhr.status);
                    // check http status code first.
                    if (http_status_code == 301 || http_status_code == 302) {
                        console.debug("got a redirect");
                        // For HTTP 301 and 302

                        // check for a Location HTTP header in the response
                        // console.debug(xhr.responseURL);

                        var redirectURL = "";

                        redirectURL = xhr.responseURL;
                        reader.readAsDataURL(xhr.response);
                        reader.onload = function (e) {

                            resolve(redirectURL);

                        };
                    } else if (http_status_code == 404) {
                        // for HTTP 404
                        // return and error message since the link has not been found.
                        console.debug("got a not found");
                        resolve("not_found");

                    } else if (http_status_code == 403) {
                        // for HTTP 403
                        // return and error message since the link has not been found.
                        console.debug("got a not found");
                        resolve("forbidden");

                    } else if (http_status_code == 405) {
                        // for HTTP 405 method not allowed
                        // the HEAD request was not allowed, try again with a GET

                        console.debug("got a not allowed");
                        resolve("forbidden");

                    } else if (http_status_code == 200) {
                        // for HTTP 200

                        // consider also looking for a html-based redirect in the
                        // body of the returned document.

                        console.debug("got a page");
                        resolve("no link");

                    } else {
                        reject("false");

                    }

                    // consider making this recursive, by calling the redirect
                    // URL to see if it results in another redirect


                };

                xhr.onerror = () => reject(xhr.statusText);
                xhr.send();
            });
        return p;
    } catch (e) {
        console.debug(e);
    }
}

function getRedirectUrl(url) {
    // console.debug("##### getRedirectUrl.start: " + url);
    try {
        var p = new Promise((resolve, reject) => {
                const xhr = new XMLHttpRequest();
                xhr.open('HEAD', url, true);
                xhr.responseType = 'blob';
                xhr.onload = function () {
                    // resolve(xhr.response);
                    var reader = new FileReader();
                    console.debug(xhr.response);
                    console.debug(xhr);

                    var http_status_code = xhr.status;

                    console.debug(xhr.status);
                    // check http status code first.
                    if (http_status_code == 301 || http_status_code == 302) {
                        console.debug("got a redirect");
                        // For HTTP 301 and 302

                        // check for a Location HTTP header in the response
                        // console.debug(xhr.responseURL);

                        var redirectURL = "";

                        redirectURL = xhr.responseURL;
                        reader.readAsDataURL(xhr.response);
                        reader.onload = function (e) {

                            resolve(redirectURL);

                        };
                    } else if (http_status_code == 404) {
                        // for HTTP 404
                        // return and error message since the link has not been found.
                        console.debug("got a not found");
                        resolve("not_found");

                    } else if (http_status_code == 403) {
                        // for HTTP 403
                        // return and error message since the link has not been found.
                        console.debug("got a not found");
                        resolve("forbidden");

                    } else if (http_status_code == 405) {
                        // for HTTP 405 method not allowed
                        // the HEAD request was not allowed, try again with a GET

                        getRedirectUrlUsingHTTPGET_async(url).then(function (res) {

                            console.debug(res);
                            console.debug("got a not found");
                            resolve("forbidden");
                        });

                    } else if (http_status_code == 200) {
                        // for HTTP 200

                        // consider also looking for a html-based redirect in the
                        // body of the returned document.

                        console.debug("got a page");
                        resolve("no link");

                    } else {
                        reject("false");

                    }

                    // consider making this recursive, by calling the redirect
                    // URL to see if it results in another redirect

                };

                xhr.onerror = () => reject(xhr.statusText);
                xhr.send();
            });
        return p;
    } catch (e) {
        console.debug(e);
    }
}

function rules_enforcement_async(sourcePageUrl, url) {

    // console.debug("# rules_enforcement begin");
    // console.debug("sourcePageUrl: " + sourcePageUrl);
    // console.debug("url: " + url);

    // apply rules to generate new URL. The rules are a collection of
    // rewrite statements applied to the submitted URL.
    // The rules are scoped in two ways: by source/destination and complete URL
    // (protocol fully-qualified domain port path), full domain (protocol
    // fully-qualified domain port ) and domain ( domain port )
    // The rewrite rules are applied in sequentially.

    // The source rules (if any) are applied first.

    // Then the destination rules are applied. And on top of any changes made
    // previosuly.

    // Two URLs are submitted: the URL of the page where the link is found, and
    // the link itself.


    var new_url = url;

    return new Promise(
        function (resolve, reject) {

        console.debug("# rules_enforcement_async begin promise");

        // start with source-based rules.
        // these are rules based on the the url of the "page" where the links are
        // located.
        console.debug("source based rewriting");
        // new_url = circumstantial_rules_enforcement(window.location.href,
        // new_url,source_url_rules,source_fulldomain_rules,source_domain_rules);
        // new_url = source_rules_enforcement(sourcePageUrl, new_url,
        // source_url_rules,
        // source_fulldomain_rules, source_domain_rules);

        source_rules_enforcement_async(sourcePageUrl, new_url).then(function (two) {
            new_url = two;
            console.debug(new_url);
            // then do destination-based rules
            // note that this is in addition to any changes made above.
            return destination_rules_enforcement_async(new_url, new_url);
        }).then(function (n) {
            new_url = n;

            console.debug(new_url);
            resolve(new_url);
        });
    });
}

// enforce rules that pertain to links found on the specified address.
function source_rules_enforcement_async(location, linkurl) {

    console.debug("# source_rules_enforcement_async begin");

    var new_url = linkurl;

    return new Promise(
        function (resolve, reject) {

        // use this to lookup any rules that may apply to links found on the
        // page of
        // this url
        var protocolfulldomainportpath = "";
        protocolfulldomainportpath = location.replace(/^(http[s]*:\/\/)([^\/]*\/)([^\?]*).*/i, '$1$2$3');

        var protocolfulldomainport = "";
        protocolfulldomainport = location.replace(/^(http[s]*:\/\/)([^\/]*\/)([^\?]*).*/i, '$1$2');

        // lookup rules for this location domain ("top"-level example domain.com
        // )
        // ignoring the first word in the fully qualified domain name

        var domainport = "";
        domainport = location.replace(/^http[s]*:\/\/[^\.]*\.([^\/]*)\/([^\?]*).*/i, '$1');

        // sourceDomainRuleStore in sourceDomainRuleDB
        // sourceHostnameRuleStore in sourceHostnameRuleDB
        // create objectstore sourceUrlRuleStore in sourceUrlRuleDB");
        console.debug("lookup: " + domainport);

        try {

            loadFromIndexedDB_async("sourceDomainRuleDB", "sourceDomainRuleStore", domainport).then(function (three) {
                console.debug("########## 0");
                // console.debug(three);

                if (three) {
                    console.debug("carry out rule on: " + new_url);
                    new_url = execute_rule(three, new_url);
                }

                // if anything returned, apply it

                // proceed with looking for more rules scopde for
                // protocolfulldomainport

                return loadFromIndexedDB_async("sourceHostnameRuleDB", "sourceHostnameRuleStore", protocolfulldomainport);
            }).then(function (one) {

                console.debug("########## 1");
                // console.debug(one);
                if (one) {
                    console.debug("carry out rule on: " + new_url);
                    new_url = execute_rule(one, new_url);

                }

                return loadFromIndexedDB_async("sourceUrlRuleDB", "sourceUrlRuleStore", protocolfulldomainportpath);
            }).then(function (two) {
                console.debug("########## 2");
                // console.debug(two);
                if (two) {
                    console.debug("carry out rule on: " + new_url);
                    new_url = execute_rule(two, new_url);
                }

                console.debug("# # # #  resolve new_url: " + new_url);
                console.debug("# source_rules_enforcement promise resolved");

                resolve(new_url);

            });

        } catch (e) {
            console.debug(e);
            resolve(new_url);

        }

    });

}

function destination_rules_enforcement_async(location, linkurl) {

    /*
     * This is subject to rewriting, for now, accept the parameter for the
     * location of the link to be rewritten, but do not use the value for
     * anything
     */

    console.debug("# destination_rules_enforcement_async begin");

    var new_url = linkurl;

    return new Promise(
        function (resolve, reject) {

        // use this to lookup any rules that may apply to links found on the
        // page of
        // this url
        var protocolfulldomainportpath = "";
        protocolfulldomainportpath = linkurl.replace(/^(http[s]*:\/\/)([^\/]*\/)([^\?]*).*/i, '$1$2$3');

        var protocolfulldomainport = "";
        protocolfulldomainport = linkurl.replace(/^(http[s]*:\/\/)([^\/]*\/)([^\?]*).*/i, '$1$2');

        // lookup rules for this location domain ("top"-level example domain.com
        // )
        // ignoring the first word in the fully qualified domain name

        var domainport = "";
        domainport = linkurl.replace(/^http[s]*:\/\/[^\.]*\.([^\/]*)\/([^\?]*).*/i, '$1');

        // sourceDomainRuleStore in sourceDomainRuleDB
        // sourceHostnameRuleStore in sourceHostnameRuleDB
        // create objectstore sourceUrlRuleStore in sourceUrlRuleDB");
        console.debug("lookup: " + domainport);

        try {

            loadFromIndexedDB_async("destinationDomainRuleDB", "destinationDomainRuleStore", domainport).then(function (three) {
                console.debug("########## 0");
                // console.debug(three);

                if (three) {
                    console.debug("carry out rule on: " + new_url);
                    new_url = execute_rule(three, new_url);
                }

                // if anything returned, apply it

                // proceed with looking for more rules scopde for
                // protocolfulldomainport

                return loadFromIndexedDB_async("destinationHostnameRuleDB", "destinationHostnameRuleStore", protocolfulldomainport);
            }).then(function (one) {

                console.debug("########## 1");
                // console.debug(one);
                if (one) {
                    console.debug("carry out rule on: " + new_url);
                    new_url = execute_rule(one, new_url);

                }

                return loadFromIndexedDB_async("destinationUrlRuleDB", "destinationUrlRuleStore", protocolfulldomainportpath);
            }).then(function (two) {
                console.debug("########## 2");
                // console.debug(two);
                if (two) {
                    console.debug("carry out rule on: " + new_url);
                    new_url = execute_rule(two, new_url);
                }

                console.debug("# # # #  resolve new_url: " + new_url);
                console.debug("# destination_rules_enforcement promise resolved");

                resolve(new_url);

            });

        } catch (e) {
            console.error(e);
            resolve(new_url);

        }

    });

}

function execute_rule_set(rule_set, url) {
    // console.debug("execute_rule_set");
    // console.debug(rule_set);
    var new_url = "";
    new_url = url;
    for (let m = 0; m < rule_set.length; m++) {
        new_url = execute_rule_step(rule_set[m], new_url);
    }
    return new_url;
}

function loadFromIndexedDB_async(dbName, storeName, id) {
    // console.debug("loadFromIndexedDB:0");
    // console.debug("loadFromIndexedDB:1 " + dbName);
    // console.debug("loadFromIndexedDB:2 " + storeName);
    // console.debug("loadFromIndexedDB:3 " + id);

    return new Promise(
        function (resolve, reject) {
        var dbRequest = indexedDB.open(dbName);

        dbRequest.onerror = function (event) {
            reject(Error("Error text"));
        };

        dbRequest.onupgradeneeded = function (event) {
            // Objectstore does not exist. Nothing to load
            event.target.transaction.abort();
            reject(Error('Not found'));
        };

        dbRequest.onsuccess = function (event) {
            // console.debug("loadFromIndexedDB:onsuccess ");

            var database = event.target.result;
            var transaction = database.transaction([storeName]);
            // console.debug("loadFromIndexedDB:transaction: " +
            // JSON.stringify(transaction));
            var objectStore = transaction.objectStore(storeName);
            // console.debug("loadFromIndexedDB:objectStore: " +
            // JSON.stringify(objectStore));
            var objectRequest = objectStore.get(id);

            // console.debug("loadFromIndexedDB:objectRequest: " +
            // JSON.stringify(objectRequest));


            try {

                objectRequest.onerror = function (event) {
                    // reject(Error('Error text'));
                    reject('Error text');
                };

                objectRequest.onsuccess = function (event) {
                    if (objectRequest.result) {
                        // console.debug("loadFromIndexedDB:result " +
                        // JSON.stringify(objectRequest.result));

                        resolve(objectRequest.result);
                    } else {
                        // reject(Error('object not found'));
                        resolve(null);

                    }
                };

            } catch (error) {
                console.error(error);

            }

        };
    });
}

function execute_rule(rule, url) {
    var new_url = "";
    new_url = url;
    try {
        // console.debug("execute_rule url: " + url);
        // console.debug("execute_rule rule: " + JSON.stringify(rule));
        // console.debug("execute_rule: " + JSON.stringify(rule.steps));
        // console.debug("execute_rule: " + rule.steps.length);
        // loop through the steps contained in this rule
        // step-order is essential
        // the output of one is the input of the next

        for (var i = 0; i < rule.steps.length; i++) {
            // console.debug("### apply step: " + JSON.stringify(rule.steps[i]) + " to " +
            // new_url);
            new_url = execute_rule_step(rule.steps[i], new_url);
        }
        // console.debug("### apply step: " + rule + " to " + new_url);
    } catch (e) {
        console.error(e);
    }
    return new_url;
}

function execute_rule_step(rule_step, url) {
    // console.debug("execute_rule_step");
    var new_url = "";
    new_url = url;
    // console.debug("### apply step: " + JSON.stringify(rule_step) + " to " +
    // new_url);

    // syntax is STEP NAME ( PARAMETER VALUE)
    var step_name = "";

    step_name = rule_step.procedure;
    console.debug("step_name: " + step_name);
    var parameter_value = "";
    try {
        // consider only cases with at most a single parameter
        parameter_value = rule_step.parameters[0].value;

    } catch (e) {
        console.error(e);
    }

    console.debug("parameter_value: " + parameter_value);
    switch (step_name) {
    case 'regexp':
        try {
            // make allowances for g and i settings
            // Parse parameter which follows the sed-syntax
            // This means that the second character is the delimiter
            var delimiter = "";
            delimiter = parameter_value.replace(/^s(.).*/i, '$1');
            var flags_ext = new RegExp("[s]*" + delimiter + "[^" + delimiter + "]*" + delimiter + "[^" + delimiter + "]*" + delimiter + "(.*)$");
            // console.debug("flags_ext: " + flags_ext);
            var flags = "";
            flags = parameter_value.replace(flags_ext, '$1').replace(/ /g, '');
            // console.debug("flags: " + flags);
            var pattern_ext = new RegExp("[s]*" + delimiter + "([^" + delimiter + "]*)" + delimiter + ".*$");
            // console.debug("pattern_ext: " + pattern_ext);
            var pattern = "";
            pattern = parameter_value.replace(pattern_ext, '$1');
            // console.debug("pattern: " + pattern);
            var val_ext = new RegExp(".*" + delimiter + "([^" + delimiter + "]*)" + delimiter + "[ gi]*$");
            var val = "";
            val = parameter_value.replace(val_ext, '$1');
            // console.debug("val_ext: " + val_ext)
            // console.debug("return val: " + val)
            // console.debug(new RegExp(pattern, flags));
            new_url = new_url.replace(new RegExp(pattern, flags), val);
        } catch (e) {
            console.debug(e);
        }
        break;
    case 'qs_param':
        // console.debug(new_url);
        // console.debug("get query string parameter named: " + parameter_value);
        var u = "";
        // remove everything infront of and behind the parameter
        var reg_exp2 = new RegExp(".*[?&]" + parameter_value + "=([^&]*).*");
        // console.debug(reg_exp2);
        u = new_url.replace(reg_exp2, '$1');
        // console.debug(u);
        // remove everything infront of the parameter
        var reg_exp1 = new RegExp(".*[\?&]" + parameter_value + "=([^&]*)$");
        // console.debug(reg_exp1);
        // console.debug(u);
        // u = url.replace(reg_exp1, '$1' );
        // new_url = url_rewrite_step_qs_param(new_url, parameter_value);
        new_url = u;
        break;
    case 'uri_decode':
        try {
            // for some reason decodeURI does not work
            new_url = new_url.replace(/%40/g, '@').replace(/%3A/g, ':').replace(/%3B/g, ';').replace(/%3C/g, '<').replace(/%3D/g, '=').replace(/%3E/g, '>').replace(/%3F/g, '?').replace(/%20/g, ' ').replace(/%21/g, '!').replace(/%22/g, '"').replace(/%23/g, '#').replace(/%25/g, '%').replace(/%26/g, '&').replace(/%28/g, '(').replace(/%29/g, ')').replace(/%2A/g, '*').replace(/%2B/g, '+').replace(/%2C/g, ',').replace(/%2D/g, '-').replace(/%2E/g, '.').replace(/%2F/g, '/').replace(/%5B/g, '[').replace(/%5C/g, '\\').replace(/%5D/g, ']').replace(/%5E/g, '^').replace(/%5F/g, '_').replace(/%60/g, "'").replace(/%25/g, '%');
        } catch (e) { // catches a malformed URI
            console.error(e);
        }
        break;
    case 'base64_decode':
        console.debug(new_url);
        new_url = atob(new_url);
        break;
    case 'JSON_path':
        console.debug(new_url);
        console.debug(JSON.parse(new_url)[parameter_value]);

        new_url = JSON.parse(new_url)[parameter_value];
        break;
    case 'replace_with':
        console.debug(new_url);
        new_url = parameter_value;
        break;
    case 'skinny_lookup':
        // lookup the URL and if it returns a HTTP 403 redirect and a Location
        // header, insert that.
        // Itterate up to three times incase on redirect leads to another.
        console.debug("lookup the URL without revealing anything");
        // new_url = parameter_value;
        break;
    default:
    }

    return new_url;

}

function setup_default_policies_async() {
    console.debug("setup_default_policies_async begin");

    try {

        return new Promise(
            function (resolve, reject) {

            var p = [];

            for (var i = 0; i < default_policies.length; i++) {
                p.push(saveToIndexedDB_async(default_policies[i].dbname, default_policies[i].dbstore, default_policies[i].keyPath, default_policies[i].policy));

            }

            // console.debug(p);
            // Using .catch:
            Promise.all(p)
            .then(values => {
                console.debug(values);

                resolve(values);
            })
            .catch(error => {
                console.error(error.message)
            });
        });
    } catch (f) {
        console.error(f);
    }

}

function DISABLEgenerate_default_link_rules_async() {

    console.debug("generate_default_link_rules begin");

    // add rule objects to database
    try {

        return new Promise(
            function (resolve, reject) {

            var p = [];
            p.push(saveToIndexedDB_async('sourceHostnameRuleDB', 'sourceHostnameRuleStore', 'keyId', {
                    keyId: 'https://www.google.com/',
                    sourceHostname: 'https://www.google.com/',
                    url_match: 'https://www.google.com/',
                    scope: 'Hostname',
                    direction: 'source',
                    steps: [{
                            procedure: "qs_param",
                            parameters: [{
                                    value: "url",
                                    notes: "read url from querystring"
                                }
                            ],
                            notes: "grab the url parameter from the querystring"
                        }, {
                            procedure: "uri_decode",
                            parameters: [],
                            notes: "uri decode"
                        }
                    ],
                    notes: '',
                    createtime: '202001010001'
                }));
            p.push(saveToIndexedDB_async('sourceHostnameRuleDB', 'sourceHostnameRuleStore', 'keyId', {
                    keyId: 'https://www.facebook.com/',
                    sourceHostname: 'https://www.facebook.com/',
                    url_match: 'https://www.facebook.com/',
                    scope: 'Domain',
                    direction: 'source',
                    steps: [{
                            procedure: "regexp",
                            parameters: [{
                                    value: "sDfbclid=[^&]*DDg",
                                    notes: "remove fbclid from qs"
                                }
                            ],
                            notes: "edit querystring"
                        }
                    ],
                    notes: 'remove tracking id from urls to thrrd parties',
                    createtime: '202001010001'
                }));

            p.push(saveToIndexedDB_async('sourceDomainRuleDB', 'sourceDomainRuleStore', 'keyId', {
                    keyId: 'google.com',
                    sourceDomain: 'google.com',
                    url_match: 'google.com',
                    scope: 'Domain',
                    direction: 'source',
                    steps: [{
                            procedure: "regexp",
                            parameters: [{
                                    value: "sDfbclid=[^&]*DDg",
                                    notes: "remove fbclid from qs"
                                }
                            ],
                            notes: "edit querystring"
                        }
                    ],
                    notes: 'remove tracking id from urls to thrrd parties',
                    createtime: '202001010001'
                }));
            p.push(saveToIndexedDB_async('sourceDomainRuleDB', 'sourceDomainRuleStore', 'keyId', {
                    keyId: 'facebook.com',
                    sourceDomain: 'facebook.com',
                    url_match: 'facebook.com',
                    scope: 'Domain',
                    direction: 'source',
                    steps: [{
                            procedure: "regexp",
                            parameters: [{
                                    value: "sDfbclid=[^&]*DDg",
                                    notes: "remove fbclid from qs"
                                }
                            ],
                            notes: "tracking token from querystring"
                        }, {
                            procedure: "regexp",
                            parameters: [{
                                    value: "s/(utm|hsa)_[a-z]*=[^&]*//g",
                                    notes: "delete parameters with names starting with utm_ and hsa_"
                                }
                            ],
                            notes: "remove suspicious parameters from querystring"
                        }
                    ],
                    notes: 'remove tracking id from urls to thrrd parties',
                    createtime: '202001010001'
                }));
            p.push(saveToIndexedDB_async('sourceHostnameRuleDB', 'sourceHostnameRuleStore', 'keyId', {
                    keyId: 'https://www.imdb.com/',
                    sourceHostname: 'https://www.imdb.com/',
                    url_match: 'https://www.imdb.com/',
                    scope: 'Hostname',
                    direction: 'source',
                    steps: [{
                            procedure: "regexp",
                            parameters: [{
                                    value: "sDcharDCHARDg",
                                    notes: "test"
                                }
                            ],
                            notes: "test"
                        }
                    ],
                    notes: 'test',
                    createtime: '202001010001'
                }));
            p.push(saveToIndexedDB_async('sourceHostnameRuleDB', 'sourceHostnameRuleStore', 'keyId', {
                    keyId: 'https://www.linkedin.com/',
                    sourceHostname: 'https://www.linkedin.com/',
                    url_match: 'https://www.linkedin.com/',
                    scope: 'Hostname',
                    direction: 'source',
                    steps: [{
                            procedure: "regexp",
                            parameters: [{
                                    value: "s/(utm|hsa)_[a-z]*=[^&]*//g",
                                    notes: "delete parameters with names starting with utm_ and hsa_"
                                }
                            ],
                            notes: "remove suspicious parameters from querystring"
                        }, {
                            procedure: "regexp",
                            parameters: [{
                                    value: "s/[&]*li_fat_id=[^&]*//g",
                                    notes: "delete qs parameter with named li_fat_id"
                                }
                            ],
                            notes: "remove extraneous parameter from querystring"
                        }
                    ],
                    notes: 'test',
                    createtime: '202001010001'
                }));
            p.push(saveToIndexedDB_async('destinationDomainRuleDB', 'destinationDomainRuleStore', 'keyId', {
                    keyId: 'ct.sendgrid.net',
                    destinationDomain: 'ct.sendgrid.net',
                    url_match: 'ct.sendgrid.net',
                    scope: 'Domain',
                    direction: 'destination',
                    steps: [{
                            procedure: "regexp",
                            parameters: [{
                                    value: "sD-D%Dg",
                                    notes: "test"
                                }
                            ],
                            notes: "test"
                        }
                    ],
                    notes: 'test',
                    createtime: '202001010001'
                }));
            p.push(saveToIndexedDB_async('destinationHostnameRuleDB', 'destinationHostnameRuleStore', 'keyId', {
                    keyId: 'https://www.facebook.com/',
                    destinationHostname: 'https://www.facebook.com/',
                    url_match: 'https://www.facebook.com/',
                    scope: 'Hostname',
                    direction: 'destination',
                    steps: [{
                            procedure: "regexp",
                            parameters: [{
                                    value: "sD\\?.*DDg",
                                    notes: "test"
                                }
                            ],
                            notes: "test"
                        }
                    ],
                    notes: 'test',
                    createtime: '202001010001'
                }));
            p.push(saveToIndexedDB_async('destinationHostnameRuleDB', 'destinationHostnameRuleStore', 'keyId', {
                    keyId: 'http://ad.doubleclick.net/',
                    destinationHostname: 'http://ad.doubleclick.net/',
                    url_match: 'http://ad.doubleclick.net/',
                    scope: 'Hostname',
                    direction: 'destination',
                    steps: [{
                            procedure: "regexp",
                            parameters: [{
                                    value: "sD.*(http[s]*://[^&]*).*D$1Dg",
                                    notes: "test"
                                }
                            ],
                            notes: "test"
                        }, {
                            procedure: "regexp",
                            parameters: [{
                                    value: "sD\\?.*DDg",
                                    notes: "test"
                                }
                            ],
                            notes: "test"
                        }
                    ],
                    notes: 'test',
                    createtime: '202001010001'
                }));
            p.push(saveToIndexedDB_async('destinationHostnameRuleDB', 'destinationHostnameRuleStore', 'keyId', {
                    keyId: 'https://www.linkedin.com/',
                    destinationHostname: 'https://www.linkedin.com/',
                    url_match: 'https://www.linkedin.com/',
                    scope: 'Hostname',
                    direction: 'destination',
                    steps: [{
                            procedure: "regexp",
                            parameters: [{
                                    value: "s/trackingId=[^&]*//g",
                                    notes: "delete trackingId from querystring"
                                }
                            ],
                            notes: "remove tracking token from querystring used inside the linkedin application"
                        }
                    ],
                    notes: 'remove tracker',
                    createtime: '202001010001'
                }));

            // boil
            // https://ad.doubleclick.net/ddm/trackclk/N1114924.158707LINKEDIN/B25010089.299078854;dc_trk_aid=491804324;dc_trk_cid=142315430;dc_lat=;dc_rdid=;tag_for_child_directed_treatment=;tfua=;gdpr=$%7BGDPR%7D;gdpr_consent=$%7BGDPR_CONSENT_755%7D;ltd=?li_fat_id=e1558f7d-a9f8-41dc-9c34-a654161f74be
            // https://ad.doubleclick.net/ddm/trackclk/N1114924.158707LINKEDIN/B25010089.299078854;dc_trk_aid=491804324;dc_trk_cid=142315430;dc_lat=;dc_rdid=;tag_for_child_directed_treatment=;tfua=;gdpr=$(GDPR);gdpr_consent=(GDPR_CONSENT_755);ltd=?li_fat_id=e1558f7d-a9f8-41dc-9c34-a654161f74be
            // down to
            // 'https://ad.doubleclick.net/ddm/trackclk/N1114924.158707LINKEDIN/B25010089.299078854;dc_trk_aid=491804324;dc_trk_cid=142315430;
            // returns
            // https://bcp.crwdcntrl.net/5/c=10025/camp_int=Advertiser_${9340650}^Campaign_${25010089}^clicks?https://www.ibm.com/cloud/bare-metal-servers?utm_content=000016GC&utm_term=10006171&p1=PSocial&p2=299078854&p3=142315430&dclid=CNjrjqPkmfACFdaNsgodXggDvQ
            // which is turn must be reduced to
            // https://www.ibm.com/cloud/bare-metal-servers

            p.push(saveToIndexedDB_async('destinationHostnameRuleDB', 'destinationHostnameRuleStore', 'keyId', {
                    keyId: 'https://ad.doubleclick.net',
                    destinationHostname: 'https://ad.doubleclick.net',
                    url_match: 'https://ad.doubleclick.net',
                    scope: 'Hostname',
                    direction: 'destination',
                    destinationHostname: 'https://ad.doubleclick.net',
                    steps: [{
                            procedure: "regexp",
                            parameters: [{
                                    value: "sD\\?.*DDg",
                                    notes: "remove the querystring"
                                }
                            ],
                            notes: "reduce to ;dc_trk_aid=11111111;dc_trk_cid=000000"
                        }, {
                            procedure: "regexp",
                            parameters: [{
                                    value: "sD\\?.*DDg",
                                    notes: "remove semmi-colon separated parameters from path where no value has been set ;dc_rdid=  "
                                }
                            ],
                            notes: "reduce to ;dc_trk_aid=11111111;dc_trk_cid=000000"
                        }
                    ],
                    notes: 'test',
                    createtime: '202001010001'
                }));

            p.push(saveToIndexedDB_async('destinationUrlRuleDB', 'destinationUrlRuleStore', 'keyId', {
                    keyId: 'https://l.facebook.com/l.php',
                    destinationUrl: 'https://l.facebook.com/l.php',
                    url_match: 'https://l.facebook.com/l.php',
                    scope: 'Url',
                    direction: 'destination',
                    steps: [{
                            procedure: "qs_param",
                            parameters: [{
                                    value: "u",
                                    notes: "read u from querystring"
                                }
                            ],
                            notes: "grab the u parameter from the querystring"
                        }, {
                            procedure: "uri_decode",
                            parameters: [{
                                    value: "N/A",
                                    notes: ""
                                }
                            ],
                            notes: "uri decode"
                        }
                    ],
                    notes: '',
                    createtime: '202001010001'
                }));
            p.push(saveToIndexedDB_async('destinationUrlRuleDB', 'destinationUrlRuleStore', 'keyId', {
                    keyId: 'https://www.google.com/url',
                    destinationUrl: 'https://www.google.com/url',
                    url_match: 'https://www.google.com/url',
                    scope: 'Url',
                    direction: 'destination',
                    steps: [{
                            procedure: "qs_param",
                            parameters: [{
                                    value: "url",
                                    notes: "read url from querystring"
                                }
                            ],
                            notes: "grab the url parameter from the querystring"
                        }, {
                            procedure: "uri_decode",
                            parameters: [{
                                    value: "N/A",
                                    notes: ""
                                }
                            ],
                            notes: "uri decode"
                        }
                    ],
                    notes: '',
                    createtime: '202001010001'
                }));
            p.push(saveToIndexedDB_async('destinationUrlRuleDB', 'destinationUrlRuleStore', 'keyId', {
                    keyId: 'https://ideas-admin.lego.com/mailing/email_link',
                    destinationUrl: 'https://ideas-admin.lego.com/mailing/email_link',
                    url_match: 'https://ideas-admin.lego.com/mailing/email_link',
                    scope: 'Url',
                    direction: 'destination',
                    steps: [{
                            procedure: "qs_param",
                            parameters: [{
                                    value: "payLoad",
                                    notes: "read payLoad from querystring"
                                }
                            ],
                            notes: "grab the payLoad parameter from the querystring"
                        }, {
                            procedure: "uri_decode",
                            parameters: [{
                                    value: "N/A",
                                    notes: ""
                                }
                            ],
                            notes: "uri decode"
                        }, {
                            procedure: "base64_decode",
                            parameters: [{
                                    value: "N/A",
                                    notes: ""
                                }
                            ],
                            notes: "BASE64 decode"
                        }, {
                            procedure: "JSON_path",
                            parameters: [{
                                    value: "url",
                                    notes: "read url from object"
                                }
                            ],
                            notes: "get piece of JSON object"
                        }
                    ],
                    notes: 'handle links embedded in emails from LEGO',
                    createtime: '202001010001'
                }));
            p.push(saveToIndexedDB_async('destinationUrlRuleDB', 'destinationUrlRuleStore', 'keyId', {
                    keyId: 'https://dagsavisen.us11.list-manage.com/track/click',
                    destinationUrl: 'https://dagsavisen.us11.list-manage.com/track/click',
                    url_match: 'https://dagsavisen.us11.list-manage.com/track/click',
                    scope: 'Url',
                    direction: 'destination',
                    steps: [{
                            procedure: "replace_with",
                            parameters: [{
                                    value: "http://www.dagsavisen.no/minside",
                                    notes: "replace"
                                }, {
                                    value: "http://www.dagsavisen.no/minside2",
                                    notes: "replace2 "
                                }, {
                                    value: "http://www.dagsavisen.no/minside3",
                                    notes: "replace 3"
                                }
                            ],
                            notes: "replace with http://www.dagsavisen.no/minside"
                        }
                    ],
                    notes: 'test',
                    createtime: '202001010001'
                }));
            p.push(saveToIndexedDB_async('destinationUrlRuleDB', 'destinationUrlRuleStore', 'keyId', {
                    keyId: 'https://www.youtube.com/watch',
                    destinationUrl: 'https://www.youtube.com/watch',
                    url_match: 'https://www.youtube.com/watch',
                    scope: 'Url',
                    direction: 'destination',
                    steps: [{
                            procedure: "regexp",
                            parameters: [{
                                    value: "sD(\\?v=[^&]*).*D$1Dg",
                                    notes: "sed statement to remove all but the v parameter"
                                }
                            ],
                            notes: "youtube videos should be short, leave only v parameter in query string"
                        }
                    ],
                    notes: 'clean youtube URLs',
                    createtime: '202001010001'
                }));
            p.push(saveToIndexedDB_async('destinationUrlRuleDB', 'destinationUrlRuleStore', 'keyId', {
                    keyId: 'https://www.flysas.com/en/flexible-booking/',
                    destinationUrl: 'https://www.flysas.com/en/flexible-booking/',
                    url_match: 'https://www.flysas.com/en/flexible-booking/',
                    scope: 'Url',
                    direction: 'destination',
                    steps: [{
                            procedure: "regexp",
                            parameters: [{
                                    value: "s/eCodsId=[^&]*//g",
                                    notes: "sed-type regexp statement to delete CodsId from url"
                                }
                            ],
                            notes: "remove piece of querystring"
                        }
                    ],
                    notes: 'SAS tracing offers',
                    createtime: '202001010001'
                }));

            console.debug(p);
            // Using .catch:
            Promise.all(p)
            .then(values => {
                console.debug(values);

                resolve(values);
            })
            .catch(error => {
                console.error(error.message)
            });
        });
    } catch (f) {
        console.error(f);
    }
}

function saveToIndexedDB_async(dbName, storeName, keyId, object) {

    console.debug("saveToIndexedDB_async:dbname " + dbName);
    console.debug("saveToIndexedDB_async:objectstorename " + storeName);
    console.debug("saveToIndexedDB_async:keyId " + keyId);
    console.debug("saveToIndexedDB_async:object " + JSON.stringify(object));

    // indexedDB = window.indexedDB || window.webkitIndexedDB ||
    // window.mozIndexedDB || window.msIndexedDB;

    return new Promise(
        function (resolve, reject) {

        // console.debug("saveToIndexedDB: 0 resolve=" + resolve )
        // console.debug("saveToIndexedDB: 0 reject=" + reject )

        // if (object.taskTitle === undefined)
        // reject(Error('object has no taskTitle.'));

        var dbRequest;

        try {

            dbRequest = indexedDB.open(dbName);
        } catch (error) {
            console.error(error);

        }
        console.debug("saveToIndexedDB_async: 1 dbRequest=" + dbRequest);

        dbRequest.onerror = function (event) {
            console.debug("saveToIndexedDB:error.open:db " + dbName);
            reject(Error("IndexedDB database error"));
        };

        console.debug("saveToIndexedDB: 2" + JSON.stringify(dbRequest));

        dbRequest.onupgradeneeded = function (event) {
            console.debug("saveToIndexedDB: 21");
            var database = event.target.result;
            console.debug("saveToIndexedDB:db create obj store " + storeName);
            var objectStore = database.createObjectStore(storeName, {
                    keyId: keyId
                });
        };

        console.debug("saveToIndexedDB: 3" + JSON.stringify(dbRequest));
        try {

            dbRequest.onsuccess = function (event) {
                console.debug("saveToIndexedDB: 31");
                var database = event.target.result;
                console.debug("saveToIndexedDB: 32");
                var transaction = database.transaction([storeName], 'readwrite');
                console.debug("saveToIndexedDB: 33");
                var objectStore = transaction.objectStore(storeName);
                console.debug("saveToIndexedDB:objectStore put: " + JSON.stringify(object));

                var objectRequest = objectStore.put(object); // Overwrite if
                // already
                // exists

                console.debug("saveToIndexedDB:objectRequest: " + JSON.stringify(objectRequest));

                objectRequest.onerror = function (event) {
                    console.debug("saveToIndexedDB:error: " + storeName);

                    reject(Error('Error text'));
                };

                objectRequest.onsuccess = function (event) {
                    console.debug("saveToIndexedDB:success: " + storeName);
                    resolve('Data saved OK');
                };
            };

        } catch (error) {
            console.error(error);

        }

    });
}
