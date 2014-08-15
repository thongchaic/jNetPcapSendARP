import java.nio.ByteBuffer;


public class ArpPacket {
	
	public byte[]src_ip;
	public byte[]src_mac;
	public byte[]dst_ip;
	public byte[]dst_mac;
	public int opcode;
	
	public ByteBuffer arp_packet;
	
	public static final byte []BROADCAST_HW = {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff};
	
	public ArpPacket(){}
	public ArpPacket(byte[]src_ip,byte[]src_mac,byte[]dst_ip,byte[]dst_mac, int opcode){
		this.src_ip = src_ip;
		this.src_mac = src_mac;
		this.dst_ip = dst_ip;
		this.dst_mac = dst_mac;
		this.opcode = opcode;
		buildARP();
	}
	private void buildARP(){
		byte[]e = new byte[14];
		//ethernet
		for(int i=0;i<6;i++){
			e[i] = (byte)0;
			e[i] = dst_mac[i];
			
			e[6+i] = (byte)0;
			e[6+i] = src_mac[i];
			
		}
		//Fix : ARP (0x0806)
		e[12] = e[13] = (byte)0;
		e[12] = (byte) 0x08;
		e[13] = (byte) 0x06;
				
		byte a[] = new byte[28];
		//Hardware Type :: Fix 0x0001 
		a[0] = a[1] = (byte)0;
		a[0] |= (byte)0x00;
		a[1] |= (byte)0x01;
		
		//Protocol Type : Fix 0x0800
		a[2] = a[3] = (byte)0;
		a[2] |= (byte)0x08;
		a[3] |= (byte)0x00;
		
		//Hawardware Size 
		a[4] = (byte)0x06;
		
		//Protocol
		a[5] = (byte)0x04;
		
		//opcode 
		a[6] = a[7] = (byte)0;
		a[6] |= (byte) ((opcode & 0xff00) >> 4);
		a[7] |= (byte) ((opcode & 0x00ff));
		
		//Sender HW / Target HW 
		for(int i=0;i<6;i++){
			a[8+i] = (byte)0;
			a[8+i] = src_mac[i];
			
			a[18+i] = (byte)0;
			a[18+i] = dst_mac[i];
			
		}
		
		//Sender IP / Target IP
		for(int i=0;i<4;i++){
			a[14+i] = (byte)0;
			a[14+i] = src_ip[i];
			
			a[24+i] = (byte)0;
			a[24+i] = dst_ip[i];
			
		}
	
		//ETH + ARP 
		byte ea[] = new byte[e.length+a.length];
		System.arraycopy(e, 0, ea, 0, e.length);
		System.arraycopy(a, 0, ea, e.length, a.length);
		arp_packet = ByteBuffer.wrap(ea);
	}
	public ByteBuffer getARPPacket(){
		return arp_packet;
	}
}
