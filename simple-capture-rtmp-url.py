import pyshark
import re

display_filter = 'rtmpt contains "rtmp" or rtmpt contains "play"'

def main():
    print("===rtmp url capture===")
    capture = pyshark.LiveCapture(interface='vEthernet (MEmuSwitch)', display_filter= display_filter, use_json=True)

    rtmp_protocol_and_hostname = ""
    path_ = ""


    for packet in capture.sniff_continuously():
        rtmpt = packet.rtmpt

        rtmp_body = []
        if "RTMP Body" in rtmpt._all_fields:
            rtmp_body = rtmpt._all_fields["RTMP Body"]

            if "String 'connect'" in rtmp_body:
                amf_object = rtmp_body["amf.object"]
                for amf_object_key in amf_object:
                    if "rtmp://" in amf_object_key:
                        rtmp_protocol_and_hostname = re.search('rtmp:\/\/.*', amf_object_key)[0].rstrip("'")
                        print(f"rtmp_host: {rtmp_protocol_and_hostname}")
            elif "String 'play'" in rtmp_body:
                for amf_object_key in rtmp_body:
                    if "String" in amf_object_key and "String 'play'" not in amf_object_key:
                        path_ = re.search("String '(.*)", amf_object_key).group(1).rstrip("'")
                        print(f"path: {path_}")
            else:
                print(rtmp_protocol_and_hostname)
        
if __name__ == "__main__":
    main()