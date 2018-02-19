
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Date;
import java.lang.System.*;
import java.text.SimpleDateFormat;
import org.xbill.DNS.*;
import org.xbill.DNS.DNSSEC.DNSSECException;


public class resolversec {
	static List<String> root_servers = new ArrayList<String>(Arrays.asList("a.root-servers.net", "b.root-servers.net", "c.root-servers.net"
			, "d.root-servers.net", "e.root-servers.net", "f.root-servers.net"
			, "g.root-servers.net", "h.root-servers.net", "i.root-servers.net"
			, "j.root-servers.net", "k.root-servers.net", "l.root-servers.net"
			, "m.root-servers.net"));

	static int q_class = DClass.IN;
	static int q_type = Type.A;
	static long q_start = 0;
	static long q_end =  0;
	static String when = "";	
	static String query = "google.com"; // Default Query
	public static void main(String[] args) throws IOException {
		
		List<String> curr_lvl_servers = root_servers;
		System.out.println(Name.root);
		
		if (args.length == 1){
            query = args[0];
            q_type = Type.A;

        }
        else if (args.length == 2){
            query= args[0];
            switch (args[1].toUpperCase()){
                case "A":
                    q_type = Type.A;
                    break;
                case "MX":
                    q_type = Type.MX;
                    break;
                case "NS":
                    q_type = Type.NS;
                    break;
                default:
                    System.out.println("DNS Query Type " + args[1] + " not supported.");
                    break;
            }
        }
        else
            System.out.println("Invalid Number of arguments. Usage: ./resolversec <host-name> [type]");
		when = new SimpleDateFormat("EEE MMM d HH:mm:ss yyyy").format(new Date());
		q_start = System.nanoTime();
		int i = 0;
		boolean verification_failed = false;
		for(; i < curr_lvl_servers.size(); i++) {
			String r_server = curr_lvl_servers.get(i);
			try {
				Name name = Name.fromString(query, Name.root);	
				Message resp = null;
				if (verification_failed == false){
						try {
								resp = getSignerResp(r_server, name, q_type);
						}
						catch(Exception e) {
								try {
										System.out.println("Socket Timeout Out (" + r_server + "). Retrying DNS Query...");
										resp = getSignerResp(r_server, name, q_type);
								}
								catch (Exception e1) {
										System.out.println("No response from DNS Query Server " + r_server);
										throw new SocketTimeoutException();
								}
						}
				}
				else{
						try {
								resp = getResp(r_server, name, q_type);
						}
						catch(Exception e) {
								try {
										System.out.println("Socket Timeout Out (" + r_server + "). Retrying DNS Query...");
										resp = getResp(r_server, name, q_type);
								}
								catch (Exception e1) {
										System.out.println("No response from DNS Query Server " + r_server);
										throw new SocketTimeoutException();
								}
						}
				}
				if (resp.toString().contains("status: NOERROR")) {
		//				System.out.println("Response: " + resp.toString());

					if (resp.getSectionArray(Section.ANSWER).length == 0) {

						RRset[] rrsets = resp.getSectionRRsets(Section.AUTHORITY);
	//					initVerification(rrsets, r_server);

						curr_lvl_servers = getAuthServers(resp);
			//			print("SERVER:" + curr_lvl_servers.get(0));
						i = -1;

						continue;
					}
					else {
						// Print A Type Record
						Record[] answers = resp.getSectionArray(Section.ANSWER);

						RRset[] rrsets = resp.getSectionRRsets(Section.ANSWER);
						if (verification_failed == false)
							initVerification(rrsets, r_server);

						for(Record ans_record: answers) {
							if (ans_record.getType() == q_type) {
								q_end = System.nanoTime();
								if (verification_failed == true)
									System.out.println("\nDNSSEC: Error Verifying Records for: " + query);
								present(resp, q_end - q_start);
								return;
							}
							else if (ans_record.getType() == Type.CNAME) {
								System.out.println("\nCNAME found: " + ans_record.rdataToString());
								query = ans_record.rdataToString();
								curr_lvl_servers = root_servers;
								i = -1;
								continue;
							}
						}
					}
				}
				else {
					verification_failed = true;
				}
			}
			catch(Exception e){
			//	System.out.println("Query Exception:\n");
	//			e.printStackTrace();
			}
		}
	}
	public static void present(Message output, long lapsed){
			System.out.println("\nQUESTION SECTION:");

			Record quest = output.getQuestion();
			System.out.println(quest.toString() + "\n");

			System.out.println("ANSWER SECTION:");

			Record[] answers = output.getSectionArray(Section.ANSWER);

			for(Record ans_record: answers) {
					if (ans_record.getType() == q_type) {
							System.out.println(ans_record.toString());
					}
			}

			System.out.println("\nQuery Time: " + lapsed/(1000000) + " msec");
			System.out.println("WHEN: " + when);
			System.out.println("MSG SIZE rcvd: " + output.numBytes());

	}
	public static void verifyZoneQuery(RRSIGRecord rec, RRset rrset, String r_server) throws IOException {
			System.out.println("Zone SIGNER: " + rec.getSigner());
			Name signer = rec.getSigner();
		int footprint = rec.getFootprint();
		DNSKEYRecord keyrec = null;
		try{
		Message resp = null;
		try {
			resp = getSignerResp(r_server, signer, Type.DNSKEY);
		}
		catch(Exception e) {
			try {
				System.out.println("Socket Timeout Out. Retrying Zone Query...");
				resp = getSignerResp(r_server, signer, Type.DNSKEY);
			}
			catch (Exception e1) {
				System.out.println("No response from Zone Query Server " + r_server);
				throw new SocketTimeoutException();
			}
		}
//		System.out.println("DNSKEY RESP: " + resp);
		RRset[] dnskey_ans_set = resp.getSectionRRsets(Section.ANSWER);
		boolean self_signed = false;
		for(RRset dnskey_ans : dnskey_ans_set) {
			Iterator<Record> sig_iter = dnskey_ans.rrs();

//			if (!sigs.hasNext()) {
//				print("DNSSEC not supported");
//				return;
//			}

//			print(dnskey_ans.toString());

			if (dnskey_ans.getType() == Type.DNSKEY){
					while(sig_iter.hasNext()) {
							DNSKEYRecord sig_record = (DNSKEYRecord) sig_iter.next();
							if (sig_record.getFootprint() == footprint) {
									System.out.println("DNS Footprint Found: " + footprint);
									keyrec = (DNSKEYRecord)sig_record;
									break;
							}
					}
			}

	//			if (keyrec == null) {
	//				print("No Valid Key Tag Found. Abort !");
	//				return;
	//			}
				
				Iterator<Record>sigs = dnskey_ans.sigs();
				if (!sigs.hasNext()) {
					print("DNSSEC not supported");
					return;
				}

				while(sigs.hasNext()) {
					RRSIGRecord sig_record = (RRSIGRecord) sigs.next();
	//				System.out.println("Here SS: " + sig_record.getFootprint());
					if (sig_record.getFootprint() == footprint) {
						self_signed = true;
						try {
							DNSSEC.verify(dnskey_ans, sig_record, keyrec);
						}
						catch (Exception e) {
							print("DNSKEY Signature Couldn't be Verified. Abort !");
							return;
						}
						System.out.println("Self-signed DNSKEY Verified for: " + sig_record.getSigner());
						break;
					}
				}
//			}
		}
		}
		catch(Exception e){
			e.printStackTrace();
			print("DNSSEC: Error verifying Record " + e.toString());
			return;
		}
	//	if (self_signed == false) {
			try {
				DNSSEC.verify(rrset, rec, keyrec);
			}
			catch (Exception e) {
				print("DNSKEY Signature Couldn't be Verified. Abort !");
				return;
			}
//			System.out.println("DNSKEY Verified");
	//	}

		try {
			verifyDS(rec, r_server);
		}
		catch (Exception e) {
			print("DS Signature Couldn't be Verified. Abort !");
			return;
		}
	}

	public static void print(String s) {
		System.out.println(s);
	}

	public static void verifyDS(RRSIGRecord rec, String r_server) throws IOException {
		Name signer = rec.getSigner();
		System.out.println("DS SIGNER: " + signer.toString());

		if (signer.toString().compareTo(".") == 0) {
			return;
		}
		
		Message resp = null;
		try {
			resp = getSignerResp(r_server, signer, Type.DS);
//			System.out.println("DS RESPONSE: " + resp.toString());
		}
		catch(Exception e) {
			try {
				System.out.println("Socket Timeout Out. Retrying DS Query...");
				resp = getSignerResp(r_server, signer, Type.DS);
			}
			catch (Exception e1) {
				System.out.println("No response from DS Query Server " + r_server);
				throw new SocketTimeoutException();
			}
		}
		RRset[] ds_ans_set = resp.getSectionRRsets(Section.ANSWER);

		for(RRset ds_ans: ds_ans_set) {
			Iterator<Record> ds_iter = ds_ans.sigs();
//			if (!ds_iter.hasNext()) {
//				print("No DS Records Found. Abort");
//				return;
//			}
			while(ds_iter.hasNext()) {
				Record ds_rec = ds_iter.next();
				
				if (ds_rec instanceof RRSIGRecord) {
					RRSIGRecord rr_rec = (RRSIGRecord) ds_rec;

					print("Validating Parent-Child DS Records...");
					verifyZoneQuery(rr_rec, ds_ans, r_server);
				}
			}

		}
		System.out.println("\nDNSSEC: SUCCESS. Record Verified");

	}

	public static List<String> getAuthServers(Message msg) {

		List<String> authservers = new ArrayList<String>();
		Record[] authrecs = msg.getSectionArray(Section.AUTHORITY);
		for(Record record: authrecs) {
			if (record.getAdditionalName() != null)
				authservers.add(strip(record.getAdditionalName().toString()));
		}
		return authservers;
	}
	private static String strip(String str) {
		int size = str.length();
		return str.substring(0, size - 1);
	}
	public static Message getSignerResp(String r_server, Name signer, int type) throws IOException {
		ExtendedResolver resolver = new ExtendedResolver();
		resolver.setEDNS(0, 0, ExtendedFlags.DO, null);
		resolver.setIgnoreTruncation(false);
		resolver.setTCP(true);
		Record record = Record.newRecord(signer, type, q_class);
		Message msg_q = Message.newQuery(record);
		Message resp = resolver.send(msg_q);
		return resp;
	}
	public static Message getResp(String r_server, Name signer, int type) throws IOException {
		SimpleResolver resolver = new SimpleResolver(r_server);
		Record record = Record.newRecord(signer, type, q_class);
		Message msg_q = Message.newQuery(record);
		Message resp = resolver.send(msg_q);
		return resp;
	}
	public static void initVerification(RRset[] rrsets, String r_server) throws IOException, DNSSECException {
		boolean sig_flag = false;
		for(RRset ans_set: rrsets) {
			Iterator<Record> sig_iter = ans_set.sigs();
			while(sig_iter.hasNext()) {
				sig_flag = true;
				RRSIGRecord rrsig = (RRSIGRecord) sig_iter.next();
				verifyZoneQuery(rrsig, ans_set, r_server);
			}
	//		System.out.println("SET: " + ans_set.sigs());
		}
		if (sig_flag == false)
			print("\nDNSSEC: DNSSEC not supported");
	}
}
