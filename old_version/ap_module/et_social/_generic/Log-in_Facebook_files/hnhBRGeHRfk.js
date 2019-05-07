/*!CK:300105382!*//*1426496951,*/

if (self.CavalryLogger) { CavalryLogger.start_js(["ua2cJ"]); }

__d("ChannelDefaults",[],function(a,b,c,d,e,f){b.__markCompiled&&b.__markCompiled();e.exports={LONGPOLL_TIMEOUT:60000,STALL_THRESHOLD:180000,MIN_RETRY_INTERVAL:5000,MAX_RETRY_INTERVAL:30000};},null);
__d("ChannelStateMap",[],function(a,b,c,d,e,f){b.__markCompiled&&b.__markCompiled();e.exports={pull:{ok:'pull!',error:'pull',error_missing:'pull',error_msg_type:'pull',clock_anomaly:'pull!',visible:'pull!',hidden:'idle!',refresh_0:'reconnect',refresh_110:'reconnect!',refresh_111:'reconnect',refresh_112:'pull',refresh_113:'pull',refresh_117:'reconnect'},reconnect:{ok:'pull!',error:'reconnect',clock_anomaly:'reconnect!',visible:'pull!',hidden:'idle!'},idle:{ok:'idle!',clock_anomaly:'idle!',visible:'pull!',hidden:'idle!'},shutdown:{clock_anomaly:'shutdown!',visible:'shutdown!',hidden:'shutdown!'}};},null);
__d("StateMachine",["setTimeoutAcrossTransitions","EventEmitter","ex"],function(a,b,c,d,e,f,g,h,i){b.__markCompiled&&b.__markCompiled();var j=0;function k(p,q){"use strict";this.idx=j++;this.machine=p;this.asap=q&&q.substr(-1)=='!';this.name=this.asap?q.substr(0,q.length-1):q;this.progress=o.NEW;this.status=null;}k.prototype.enter=function(){"use strict";this.machine.enter_private(this);};k.prototype.exit=function(p){"use strict";this.machine.exit_private(this,p);};k.prototype.toString=function(){"use strict";return this.name+'('+this.progress+','+this.status+')';};var l='_ABORT_';for(var m in h)if(h.hasOwnProperty(m))o[m]=h[m];var n=h===null?null:h.prototype;o.prototype=Object.create(n);o.prototype.constructor=o;o.__superConstructor__=h;function o(p,q){"use strict";h.call(this);this.$StateMachine0=p;this.$StateMachine1=q;this.$StateMachine2=0;this.$StateMachine3=[];this.$StateMachine4=Date.now();}o.prototype.$StateMachine5=function(p){"use strict";this.$StateMachine3.push((Date.now()-this.$StateMachine4)+': '+p);if(this.$StateMachine3.length>40)this.$StateMachine3=this.$StateMachine3.splice(-20);};o.prototype.getState=function(){"use strict";return this.$StateMachine6;};o.prototype.setDelay=function(p){"use strict";this.$StateMachine2=p||0;return this;};o.prototype.getDelay=function(){"use strict";return this.$StateMachine2;};o.prototype.enter=function(p){"use strict";this.enter_private(new k(this,p));};o.prototype.enter_private=function(p){"use strict";this.$StateMachine5('enter '+p+', '+this.$StateMachine6);if(this.$StateMachine6&&this.$StateMachine6!=p)this.$StateMachine6.exit(l);this.$StateMachine6=p;if(p.asap){delete p.asap;if(this.$StateMachine1.enter)this.$StateMachine1.enter(p);p.progress=o.ENTERED;}else{p.progress=o.PENDING;p.asap=true;p.$StateMachine7=g(function(){p.enter();},this.$StateMachine2);}this.emit(o.ENTER,p);};o.prototype.exit=function(p){"use strict";this.exit_private(this.$StateMachine6,p);};o.prototype.exit_private=function(p,q){"use strict";this.$StateMachine5('exit '+p+', '+q+', '+this.$StateMachine6);if(!p||p!=this.$StateMachine6)throw new Error(i('Invalid state: %s, history: %s',p,this.$StateMachine3.join('|')));if(p.progress==o.EXITED)return;p.status=q;p.progress=o.EXITED;if(p.$StateMachine7){clearInterval(p.$StateMachine7);p.$StateMachine7=null;}this.$StateMachine6=null;if(p&&this.$StateMachine1.exit)this.$StateMachine1.exit(p);p.exited=true;this.emit(o.EXIT,p);if(q!=l){var r=this.$StateMachine0[p.name];if(!r||!r[q])throw new Error(i('No exit for state:%s, status: %s',p.name,q));this.enter(r[q]);}};o.ENTER='enter';o.EXIT='exit';o.NEW='new';o.PENDING='pending';o.ENTERED='entered';o.EXITED='exited';e.exports=o;},null);
__d("rand32",[],function(a,b,c,d,e,f){b.__markCompiled&&b.__markCompiled();function g(){return Math.floor(Math.random()*4294967295);}e.exports=g;},null);
__d("MChannelManager",["Banzai","ChannelClientConfig","ChannelDefaults","ChannelStateMap","Clock","LogHistory","MLogger","MRequest","MURI","StateMachine","URI","Visibility","copyProperties","rand32","setTimeoutAcrossTransitions"],function(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u){b.__markCompiled&&b.__markCompiled();var v,w='ok',x='error',y='error_missing',z=60000,aa=null,ba=null,ca=null,da=null,ea=null,fa=-1,ga=null,ha=0,ia={enter:function(ra){if(da){da.abort();da=null;}switch(ra.name){case 'pull':if(!ba.uri)break;if(ba.disabled)break;var sa=new q(ba.uri),ta={channel:ba.user_channel,seq:ca,profile:'mobile',partition:ba.partition,sticky_token:fa,msgs_recv:ha,cb:t()};if(ba.chat_enabled)ta.state='active';if(ga)ta.sticky_pool=ga;if(ba.uid&&ba.viewerUid){ta.uid=ba.uid;ta.viewerUid=ba.viewerUid;}da=(new n(sa+'')).setCORS(true).setMethod('GET').setData(ta).setRaw(true);da.listen('open',function(va){va.getTransport().withCredentials=true;});da.listen('done',function(va){la(ra,va);});da.listen('error',function(){la(ra);});break;case 'reconnect':var ua=new o('/a/channel/reconnect.php').setAsync(true);da=(new n(ua+'')).setMethod('GET');da.listen('done',function(va){ka(ra,va);});da.listen('error',function(va){va.isHandled=true;ka(ra);});break;default:}if(da)da.send();},exit:function(ra){if(ra.status==='ok'){if(ra.name==='pull')v.setDelay(0);}else if(!(ra.status==null)){var sa=v.getDelay();sa=sa>0?(sa*2):aa.MIN_RETRY_INTERVAL;sa=Math.min(sa,aa.MAX_RETRY_INTERVAL);v.setDelay(sa);}if(da){da.abort();da=null;}}};function ja(ra){ea=ra;}function ka(ra,sa){if(!sa){m.warn('_onReconnectError: reconnect request error');ra.exit(x);}else if(sa.user_channel){ba=sa;ca=ba.seq;ra.exit(w);}else{m.warn('_onReconnectError: bad reconnect response - %s',JSON.stringify(sa));ra.exit(x);}}function la(ra,sa){var ta=w;if(!sa){ra.exit(x);return;}switch(sa.t){case 'refresh':case 'refreshDelay':ta='refresh_'+(sa.reason||0);break;case 'fullReload':ta=y;break;case 'continue':break;case 'lb':var ua=sa.lb_info;if(ua){ha=0;fa=ua.sticky;var va="http://";if(ba.is_secure_uri)va="https://";if('pool' in ua){ga=ua.pool;}else ba.uri=va+ua.vip+'.facebook.com/pull';}else m.error('bad lb info from channel proxy');break;case 'msg':var wa=sa.seq-sa.ms.length;for(var xa=0;xa<sa.ms.length;xa++){var ya=wa+xa;ha++;if(ya>=ca){if(ea)sa.ms[xa]=ea(sa.ms[xa]);v.emit(v.CHANNEL_MESSAGE,sa.ms[xa]);}}break;case 'heartbeat':break;default:ta=x;if(g.isEnabled('mchannel_detailed_log')){m.warn('_onRequestSuccess: invalid channel response, resending request: %s',JSON.stringify(sa));}else m.warn('_onRequestSuccess: invalid channel response, sending request again.');break;}if('seq' in sa)ca=sa.seq;ra.exit(ta);}function ma(){if(!v.xhrEnabled||aa)return;aa=s(i,h.config);ba=h.info;ca=ba.seq;k.addListener(k.ANOMALY,function(){v.exit('clock_anomaly');});r.addListener(r.HIDDEN,function(){v.exit('hidden');});r.addListener(r.VISIBLE,function(){v.exit('visible');});a.onbeforeunload=function(){if(da)da.abort();};if('sticky_token' in ba)fa=ba.sticky_token;na();}function na(){v.setDelay(aa.MIN_RETRY_INTERVAL);v.enter(ba.uri?'pull!':'reconnect!');}v=new p(j,ia);v.startChannel=ma;v.setTransform=ja;v.xhrEnabled=!!a.XMLHttpRequest;v.CHANNEL_MESSAGE='channel_message';var oa;function pa(){v.emit(p.ENTER,{name:'stall',progress:p.ENTERED});if(g.isEnabled('mchannel_jumpstart'))na();}function qa(ra){l.getInstance('channel').log(ra.name,ra.status||ra.progress);if(ra.name!=='stall'){clearTimeout(oa);oa=u(pa,z);}}v.addListener(p.ENTER,qa);v.addListener(p.EXIT,qa);e.exports=v;},null);
__d("MHelpHeader",["Stratcom"],function(a,b,c,d,e,f,g){b.__markCompiled&&b.__markCompiled();var h={init:function(){g.listen('m:page:loading',null,function(){if(window.location.pathname.match(/^\/help(\/|$)/)===null){g.removeCurrentListener();location.reload();}});}};e.exports=h;},null);
__d("MBackButton",["Stratcom"],function(a,b,c,d,e,f,g){b.__markCompiled&&b.__markCompiled();var h=false,i=function(){if(h)return;h=true;g.listen('click','back-button',function(event){if(history.length>1){event.kill();history.go(-1);}});};f.main=i;},null);
__d("MobileZeroRewriteURL",["MChannelManager"],function(a,b,c,d,e,f,g){b.__markCompiled&&b.__markCompiled();var h=null,i=null;function j(n){if(!n)return;h=n.regex_matcher;i=n.regex_replacer;for(var o=0;o<h.length;o++){var p=h[o];if(p.indexOf('^')===0)p=p.substr(1);var q=new RegExp(p,"i");h[o]=q;}g.setTransform(k);}function k(n){if(!n||!h)return n;l(n);return n;}function l(n){if(Array.isArray(n)){for(var o=0;o<n.length;o++)m(n,o);}else for(var p in n)if(n.hasOwnProperty(p))m(n,p);}function m(n,o){var p=n[o],q=typeof(p);if(q==="object"){l(p);}else if(q==="string"&&p.indexOf("<img")>=0){p=p.replace(/<img[^>]*>/gi,function(r){for(var s=0;s<h.length;s++){var t=h[s];if(t.test(r))return r.replace(t,i[s]);}return r;});n[o]=p;}}f.main=j;},null);