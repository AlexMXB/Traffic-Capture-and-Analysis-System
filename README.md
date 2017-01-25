# Traffic-Capture-and-Analysis-System
Project sample in CMRI
Auto sniff, capture, dump,and extract potential-feature-list to boost automation of labeling system for APP/WEB user.
kind of fiddler, wireshark or charles to perform DPI and protocol analysis over the internet.
sample_list_show:
URI	                  Method	                        User-agent	                            Body
/unionid/v1/generate	POST	Dalvik/2.1.0 (Linux; U; Android 6.0.1; MI 4LTE MIUI/666.4.14)	{"unionid":"2eb263d42123ab54e83277bd4c06e069","data":{"bluetooth_mac":"","pseudo_uniqueid":"357616666673246","imei":"865931022792071","serial_number":"850c200e","model":"MI 4LTE","android_id":"8bae983aa687dd48","type":"Android","brand":"Xiaomi","wlan_mac":"02:00:00:00:00:00"}}
			
/config/v1/keyvalue.json?appname=group&platform=android&version=2.8.1	GET	Dalvik/2.1.0 (Linux; U; Android 6.0.1; MI 4LTE MIUI/666.4.14)	
			
/config/v1/keyvalue.json?appname=group&platform=android&version=2.8&__vhost=api.mobile.meituan.com&utm_source=wandoujia&utm_medium=android&utm_term=381&version_name=6.8.1&utm_content=865931022792071&utm_campaign=AgroupBpushC0D200E0H145673&ci=1&msid=8659310227920711464400453349&uuid=521BF886936908E7E1A697E70B264C5B3B1280683785440C9BF1C463CF51E893&userid=65687079&__reqTraceID=9a7a9a7a-85c6-4e39-9908-23b320c9ee23&__skck=6a375bce8c66a0dc293860dfa83833ef&__skts=1464515490418&__skua=594476d291cbea2d29902a8d800824bd&__skno=0b1be2df-0e16-4532-b481-f56c067848b1&__skcy=K9qZ8iLSiWDSg28LaeM0%2FbVxta8%3D	GET	AiMeiTuan /Xiaomi-6.0.1-MI 4LTE-1920x1080-480-6.8.1-381-865931022792071-wandoujia	
			
/group/v1/user/65687079/ordercenternew/unused?token=JXylHXJemQmAyrBVhhJTQJJ4pqoAAAAAOgIAAKpw00653emR9wW8FN8VNTQFUzOIQiUmsqZLP2s8zLY1o7JFFVo7Zr96yF8E70EaRQ&dealFields=imgurl%2Csmstitle%2Crefund%2Cfakerefund%2Csevenrefund%2Chowuse%2Ctitle%2Cprice%2Cvalue%2Cbrandname%2Ccate%2Csubcate%2Cmenu%2Cterms%2Crdploc%2Cmname%2Cctype%2Cvoice%2Ccoupontitle%2Cktvplan%2Cbookingphone%2CattrJson%2Cpricecalendar%2Cisappointonline%2Coptionalattrs%2Cslug%2Cend%2Cstatus%2Crdcount%2Ccouponendtime%2Cexpireautorefund%2CiUrl&moreinfo=hotel&__vhost=api.mobile.meituan.com&utm_source=wandoujia&utm_medium=android&utm_term=381&version_name=6.8.1&utm_content=865931022792071&utm_campaign=AgroupBpushC0D200E0H145673&ci=1&msid=8659310227920711464400453349&uuid=521BF886936908E7E1A697E70B264C5B3B1280683785440C9BF1C463CF51E893&userid=65687079&__reqTraceID=3bd88ff8-77d1-460a-87fe-f468951dd303&__skck=6a375bce8c66a0dc293860dfa83833ef&__skts=1464515490706&__skua=594476d291cbea2d29902a8d800824bd&__skno=6a5b7034-084e-4e69-82cd-f263a00b20e0&__skcy=qOYieEcI4gAs7TVUnKVROnevFOQ%3D	GET	AiMeiTuan /Xiaomi-6.0.1-MI 4LTE-1920x1080-480-6.8.1-381-865931022792071-wandoujia	

......


