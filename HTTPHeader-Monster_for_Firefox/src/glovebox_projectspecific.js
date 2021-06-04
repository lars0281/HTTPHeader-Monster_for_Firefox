export { 
	default_policies,
	index_db_config,
	};


import {
	create_indexeddb_async,
    deleteFromIndexedDB_async,
    dump_db,
    flush_all_keys_async,
	loadFromIndexedDB_async,
    READ_DB_async,
    saveToIndexedDB_async
}
from "./utils/glovebox_db_ops.js"


var index_db_config = [{ dbname: "sourceHostnameRuleDB", 
	objectstore: [
		{name:"sourceHostnameRuleStore",
			keyPath: "keyId", 
			autoIncrement: false, 
			index:[
				{
				n: "keyId",
				o: "keyId",  
				unique: "true" }
				]
		}
	]
},{ dbname: "sourceUrlRuleDB", 
objectstore: [
	{name:"sourceUrlRuleStore",
		keyPath: "keyId", 
		autoIncrement: false, 
		index:[
			{
			n: "keyId",
			o: "keyId",  
			unique: "true" }
			]
	}
]
},{ dbname: "sourceDomainRuleDB", 
objectstore: [
{name:"sourceDomainRuleStore",
	keyPath: "keyId", 
	autoIncrement: false, 
	index:[
		{
		n: "keyId",
		o: "keyId",  
		unique: "true" }
		]
}
]
},{ dbname: "destinationHostnameRuleDB", 
objectstore: [
{name:"destinationHostnameRuleStore",
	keyPath: "keyId", 
	autoIncrement: false, 
	index:[
		{
		n: "keyId",
		o: "keyId",  
		unique: "true" }
		]
}
]
},{ dbname: "destinationUrlRuleDB", 
objectstore: [
{name:"destinationUrlRuleStore",
	keyPath: "keyId", 
	autoIncrement: false, 
	index:[
		{
		n: "keyId",
		o: "keyId",  
		unique: "true" }
		]
}
]
},{ dbname: "destinationDomainRuleDB", 
objectstore: [
{name:"destinationDomainRuleStore",
	keyPath: "keyId", 
	autoIncrement: false, 
	index:[
		{
		n: "keyId",
		o: "keyId",  
		unique: "true" }
		]
}
]
}];



var default_policies = [{dbname:'sourceHostnameRuleDB',dbstore:'sourceHostnameRuleStore', keyPath: 'keyId', policy:{
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
      }},{  dbname:'sourceHostnameRuleDB', dbstore:'sourceHostnameRuleStore',keyPath:'keyId', policy:{
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
                }},{ dbname:'sourceDomainRuleDB',dbstore: 'sourceDomainRuleStore', keyPath:'keyId', policy: {
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
                }},{ dbname:'sourceDomainRuleDB',dbstore: 'sourceDomainRuleStore', keyPath:'keyId',policy:{
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
                }},{   dbname:'sourceHostnameRuleDB', dbstore: 'sourceHostnameRuleStore', keyPath: 'keyId', policy: {
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
                }},{  dbname: 'sourceHostnameRuleDB', dbstore: 'sourceHostnameRuleStore', keyPath: 'keyId', policy: {
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
                }},{ dbname: 'destinationDomainRuleDB', dbstore: 'destinationDomainRuleStore', keyPath: 'keyId', policy: {
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
                }},{ dbname:'destinationHostnameRuleDB', dbstore:'destinationHostnameRuleStore',keyPath: 'keyId', policy: {
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
                }},{ dbname: 'destinationHostnameRuleDB', dbstore: 'destinationHostnameRuleStore', keyPath: 'keyId', policy: {
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
                }},{ dbname: 'destinationHostnameRuleDB', dbstore: 'destinationHostnameRuleStore',kayPath: 'keyId', policy: {
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
                }},{ dbname:'destinationHostnameRuleDB',dbstore: 'destinationHostnameRuleStore', keyPath: 'keyId', policy:{
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
                }},{dbname: 'destinationUrlRuleDB', dbstore: 'destinationUrlRuleStore',keyPath: 'keyId', policy: {
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
                }},{dbname:'destinationUrlRuleDB', dbstore:'destinationUrlRuleStore', keyPath: 'keyId', policy: {
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
                }},{ dbname: 'destinationUrlRuleDB', dbstore: 'destinationUrlRuleStore', keyPath: 'keyId', policy: {
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
                }},{ dbname:'destinationUrlRuleDB',dbstore:'destinationUrlRuleStore', keyPath: 'keyId', policy: {
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
                }},{ dbname: 'destinationUrlRuleDB', dbstore: 'destinationUrlRuleStore', keyPath: 'keyId', policy: {
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
                }},{ dbname: 'destinationUrlRuleDB',dbstore: 'destinationUrlRuleStore',keyPath: 'keyId', policy: {
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
                }}
	
	];





