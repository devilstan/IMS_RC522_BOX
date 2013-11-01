/*
* Name：RFID.pde
* Create：www.electrodragon.com
* Create date：2011.09.19
* Function：Mifare1 searching card →prevent conflict→ select card →read write pins
*/
// the sensor communicates using SPI, so include the library:
#include <SPI.h>
#include <avr/wdt.h>

#define	uchar	unsigned char
#define	uint	unsigned int

//data array maxium length
#define MAX_LEN 16

/////////////////////////////////////////////////////////////////////
//set the pin
/////////////////////////////////////////////////////////////////////
const int chipSelectPin = 10;
const int NRSTPD = 5;

//MF522 command bits
#define PCD_IDLE              0x00               //NO action; cancel current commands
#define PCD_AUTHENT           0x0E               //verify password key
#define PCD_RECEIVE           0x08               //receive data
#define PCD_TRANSMIT          0x04               //send data
#define PCD_TRANSCEIVE        0x0C               //send and receive data
#define PCD_RESETPHASE        0x0F               //reset
#define PCD_CALCCRC           0x03               //CRC check and caculation

//Mifare_One card command bits
#define PICC_REQIDL           0x26               //Search the cards that not into sleep mode in the antenna area 
#define PICC_REQALL           0x52               //Search all the cards in the antenna area
#define PICC_ANTICOLL         0x93               //prevent conflict
#define PICC_SElECTTAG        0x93               //select card
#define PICC_AUTHENT1A        0x60               //verify A password key
#define PICC_AUTHENT1B        0x61               //verify B password key
#define PICC_READ             0x30               //read 
#define PICC_WRITE            0xA0               //write
#define PICC_DECREMENT        0xC0               //deduct value
#define PICC_INCREMENT        0xC1               //charge up value
#define PICC_RESTORE          0xC2               //Restore data into buffer
#define PICC_TRANSFER         0xB0               //Save data into buffer
#define PICC_HALT             0x50               //sleep mode


//THe mistake code that return when communicate with MF522
#define MI_OK                 0
#define MI_NOTAGERR           1
#define MI_ERR                2


//------------------MFRC522 register ---------------
//Page 0:Command and Status
#define     Reserved00            0x00    
#define     CommandReg            0x01    
#define     CommIEnReg            0x02    
#define     DivlEnReg             0x03    
#define     CommIrqReg            0x04    
#define     DivIrqReg             0x05
#define     ErrorReg              0x06    
#define     Status1Reg            0x07    
#define     Status2Reg            0x08    
#define     FIFODataReg           0x09
#define     FIFOLevelReg          0x0A
#define     WaterLevelReg         0x0B
#define     ControlReg            0x0C
#define     BitFramingReg         0x0D
#define     CollReg               0x0E
#define     Reserved01            0x0F
//Page 1:Command     
#define     Reserved10            0x10
#define     ModeReg               0x11
#define     TxModeReg             0x12
#define     RxModeReg             0x13
#define     TxControlReg          0x14
#define     TxAutoReg             0x15
#define     TxSelReg              0x16
#define     RxSelReg              0x17
#define     RxThresholdReg        0x18
#define     DemodReg              0x19
#define     Reserved11            0x1A
#define     Reserved12            0x1B
#define     MifareReg             0x1C
#define     Reserved13            0x1D
#define     Reserved14            0x1E
#define     SerialSpeedReg        0x1F
//Page 2:CFG    
#define     Reserved20            0x20  
#define     CRCResultRegM         0x21
#define     CRCResultRegL         0x22
#define     Reserved21            0x23
#define     ModWidthReg           0x24
#define     Reserved22            0x25
#define     RFCfgReg              0x26
#define     GsNReg                0x27
#define     CWGsPReg	          0x28
#define     ModGsPReg             0x29
#define     TModeReg              0x2A
#define     TPrescalerReg         0x2B
#define     TReloadRegH           0x2C
#define     TReloadRegL           0x2D
#define     TCounterValueRegH     0x2E
#define     TCounterValueRegL     0x2F
//Page 3:TestRegister     
#define     Reserved30            0x30
#define     TestSel1Reg           0x31
#define     TestSel2Reg           0x32
#define     TestPinEnReg          0x33
#define     TestPinValueReg       0x34
#define     TestBusReg            0x35
#define     AutoTestReg           0x36
#define     VersionReg            0x37
#define     AnalogTestReg         0x38
#define     TestDAC1Reg           0x39  
#define     TestDAC2Reg           0x3A   
#define     TestADCReg            0x3B   
#define     Reserved31            0x3C   
#define     Reserved32            0x3D   
#define     Reserved33            0x3E   
#define     Reserved34			  0x3F
//-----------------------------------------------

//4 bytes Serial number of card, the 5 bytes is verfiy bytes
uchar serNum[5];
uchar serNum_prev[5];
uchar card_type[2];
boolean diff_flag = false;
uchar  writeData[16]={0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100};  //initialize to 100 USD
uchar  moneyConsume = 18 ;  //Deduct 18 USD
uchar  moneyAdd = 10 ;  //Charge up 10 USD
//buffer A password, 16 buffer, the passowrd of every buffer is 6 byte 
uchar sectorKeyA[16][16] = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
							{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
							{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
							{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
							};
uchar comstate;
uchar activate_code;
uchar sendData[16];
String inputString_copy = "";
String inputString = "";         // a string to hold incoming data
uchar inputHeadercode[4] = {19, 81, 01, 16};
int header_hit_counter;
unsigned int checksum;
boolean stringComplete = false;  // whether the string is complete
boolean chksum_OK = false;
uchar tctrl;
uchar t1;
uchar t2;
uchar ttotal;
int c;
byte readc;
unsigned int rc;

void setup() {                
	Serial.begin(9600);                       // RFID reader SOUT pin connected to Serial RX pin at 2400bps 
	// start the SPI library:
	SPI.begin();
        pinMode(6, OUTPUT); 
        pinMode(7, OUTPUT); 
	pinMode(chipSelectPin,OUTPUT);             // Set digital pin 10 as OUTPUT to connect it to the RFID /ENABLE pin 
	digitalWrite(chipSelectPin, LOW);          // Activate the RFID reader
	pinMode(NRSTPD,OUTPUT);               // Set digital pin 10 , Not Reset and Power-down
	digitalWrite(NRSTPD, HIGH);
        inputString.reserve(16);
        inputString_copy.reserve(16);
	MFRC522_Init();
        comstate = 0;
        
        TCCR1A = 0x00;                // Normal mode, just as a Timer
        TCCR1B |= _BV(CS12);          // prescaler = CPU clock/1024
        TCCR1B &= ~_BV(CS11);      
        TCCR1B |= _BV(CS10);   
        TIMSK1 |= _BV(TOIE1);         // enable timer overflow interrupt
        TCNT1 = -3125;               // Ticks for 0.2 second @16 MHz,prescale=1024
        tctrl = 0;
        t1 = 255;
        t2 = 255;
        ttotal = 255;
        rc = 0;
        checksum = 0;
        wdt_enable (WDTO_1S);  // reset after one second, if no "pat the dog" received
}

void loop()
{
	uchar i, tmp;
	uchar status;
	uchar str[MAX_LEN];
	uchar RC_size;
	uchar blockAddr; // select the operating block address 0 to 63
        uchar activate = 0;
        
        if ( bitRead(tctrl, 0) == 0 ) {
            ttotal = 15;    //unit:0.2s
        }
        if ( bitRead(tctrl, 1) == 0 ) {
            t1 = 7;    //unit:0.2s
        }
        if ( bitRead(tctrl, 2) == 0 ) {
            t2 = 7;    //unit:0.2s
        }

	//Look for the card, return the card type
	status = MFRC522_Request (PICC_REQIDL, str);
	if (status == MI_OK)
        {
            memset( sendData, 0, 16 );
            memcpy( sendData+4+1, str, 2 );
            activate |= 1 << 0;
	}
        else {
            activate &= ~( 1 << 0 );
        }


	// Anti-collision, return the card serial number 4-byte
	status = MFRC522_Anticoll(str);
	if (status == MI_OK)
	{
            memcpy( serNum, str, 5 );
            memcpy( sendData+4+1+2, str, 5 );
            activate |= 1 << 1;
	}
        else {
            activate &= ~( 1 << 1 );
        }

	//Election card, return the card capacity
	RC_size = MFRC522_SelectTag (serNum);
	if (RC_size != 0)
	{
            activate |= 1 << 2;
	}
        else {
            activate &= ~( 1 << 2 );
        }
        //RFID流程正確，啟動處理區分activate_code = 0x16(其他地方不能修改)
        if ( activate == 0x07 ) {
            memcpy(sendData, inputHeadercode, 4);
            activate_code = 0x16;
            tctrl |= (1 << 0);  //啟動總逾時時間
        }
        //檢查總逾時時間
        if ( !ttotal ) {
            clearAllState();
            tctrl &= ~(1 << 0);
            tctrl &= ~(1 << 1);
            tctrl &= ~(1 << 2);
        }
        //訊息處理流程
        wdt_reset();
        int sum_temp = 0;
        int mychksum_t = 0;
        String s;
        int mycouter = 0;
        switch ( activate_code ) {
            case 0x16:
                //啟動通信，並通知ＰＣ端準備接收
                switch ( comstate ) {
                case 0:
                    sendData[4] = 0x16;
                    sum_temp = 0;
                    for ( mycouter = 0; mycouter < 15; mycouter++ ) {
                        sum_temp += (int)sendData[mycouter];
                    }
                    mychksum_t = 0xffff - sum_temp;
                    s = decToHex( mychksum_t, 4 );
                    sendData[15] = (uchar)hexToDec( s.substring(2) );
                    digitalWrite(7, HIGH);
                    checksum = 0;
                    Serial.write((const uint8_t*)sendData, sizeof(sendData));
                    digitalWrite(7, LOW);
                    tctrl |= (1 << 1);
                    comstate = 1;
                    break;
                case 1:
                    if ( t1 > 0 ) {
                        if ( stringComplete && chksum_OK ) {
                            if ( inputString_copy[4] == (0x16+0x11) ) {
                                //Serial.println("OK");
                                comstate = 2;    //timeout前取得正確ＡＣＫ 則進入狀態2
                                sendData[13] = 1;
                                tctrl &= ~(1 << 1);
                                //Serial.println("0");
                            }
                            else {
                                comstate = 0;    //timeout前取得錯誤ＡＣＫ 則回到狀態0
                                sendData[13] = 2;
                                sendData[14] = inputString[0];
                                //tctrl &= ~(1 << 1);
                                //Serial.println("1");
                            }
                            // clear the string:
                            inputString = "";
                            inputString_copy = "";
                            rc = 0;
                            stringComplete = false;
                            chksum_OK = false;
                        }
                        else {
                            comstate = 1;        //timeout前等待接收時 維持狀態1
                            sendData[13] = 3;
                            //Serial.println("2");
                        }
                    }
                    else {
                        comstate = 0;            //timeout! 則回到狀態0
                        sendData[13] = 4;
                        tctrl &= ~(1 << 1);
                        header_hit_counter = 0;
                        rc = 0;
                        //Serial.println("c1 timeout and return");
                    }
                    //Serial.println("c1");
                    break;
                case 2:
                    sendData[4] = 0x69;
                    //sendData[23] = 0x1F;
                    c = 0;
                    sum_temp = 0;
                    for ( mycouter = 0; mycouter < 15; mycouter++ ) {
                        sum_temp += (int)sendData[mycouter];
                    }
                    mychksum_t = 0xffff - sum_temp;
                    s = decToHex( mychksum_t, 4 );
                    sendData[15] = (uchar)hexToDec( s.substring(2) );
                    digitalWrite(7, HIGH);
                    Serial.write((const uint8_t*)sendData, sizeof(sendData));
                    digitalWrite(7, LOW);
                    tctrl |= (1 << 2);
                    comstate = 3;
                    break;
                case 3:
                    if ( t2 ) {
                        if ( stringComplete && chksum_OK ) {
                            if ( inputString_copy[4] == (0x69+0x11) ) {
                                comstate = 4;    //timeout前取得正確ＡＣＫ 則進入狀態4
                                sendData[13] = 5;
                                //Serial.print("1");
                                clearAllState();
                                tctrl &= ~(1 << 2);
                            }
                            else {
                                comstate = 2;    //timeout前取得錯誤ＡＣＫ 則回到狀態2
                                sendData[13] = 6;
                                sendData[14] = inputString[0];
                                //Serial.print("2");
                                //tctrl &= ~(1 << 2);
                            }
                            // clear the string:
                            inputString = "";
                            inputString_copy = "";
                            rc = 0;
                            chksum_OK = false;
                            stringComplete = false;
                        }
                        else {
                            comstate = 3;        //timeout前等待接收時 維持狀態3
                            sendData[13] = 7;
                            //Serial.print("3");
                        }
                    }
                    else {
                        //t2=0 (timeout)
                        comstate = 2;            //timeout! 則回到狀態2
                        sendData[13] = 8;
                        tctrl &= ~(1 << 2);
                        header_hit_counter = 0;
                        rc = 0;
                        //Serial.println("c3 timeout and return");
                    }
                    //Serial.println("c1");
                    break;
                default:
                    comstate = 0;
                    break;
                }
        default:
            break;
        }

	//Card Reader
	blockAddr = 7; //data block 7
	//status = MFRC522_Auth (PICC_AUTHENT1A, blockAddr, sectorKeyA [blockAddr / 4], serNum); //authentication
	
        status = MI_ERR;
        if (status == MI_OK)
	{
		//Read data
		blockAddr = blockAddr - 3;
		status = MFRC522_Read (blockAddr, str);
		if (status == MI_OK)
		{
			Serial.println ("Read from the card, the data is:");
			for (i = 0; i <16; i ++)
			{
				Serial.print (str [i], HEX);
				Serial.print (",");
			}
			Serial.println ("");
		}
	}
	//Serial.println ("");
        if ( activate == 0x07 ) {
	    MFRC522_Halt(); // command card into hibernation
        }
        //delay(50);
}

ISR (TIMER1_OVF_vect)
{   
    if ( t1 > 0 ) t1--;
    if ( t2 > 0 ) t2--;
    if ( ttotal > 0 ) ttotal--;
    TCNT1 = -3125;               // Ticks for 1 second @16 MHz,prescale=1024
}

/*
  SerialEvent occurs whenever a new data comes in the
 hardware serial RX.  This routine is run between each
 time loop() runs, so using delay inside loop can delay
 response.  Multiple bytes of data may be available.
 */
void serialEvent() {
    
  while (Serial.available()) {
    // get the new byte:
    digitalWrite(6, HIGH);
    char inChar = (char)Serial.read();
    digitalWrite(6, LOW); 
    // add it to the inputString:
    //Serial.println("");
    //Serial.println(checksum, DEC);
    switch ( rc ) {
    case 0 ... 3:
        inputString += inChar;
        //接收byte跟header比, 相同則繼續下次讀取, 相異則重置rc與inputString
        if ( (uchar)inChar == inputHeadercode[rc] ) {
            checksum += (uchar)inChar;
            rc++;
        } else {
            checksum = 0;
            rc = 0;
            inputString = "";
        }
        break;
    case 4 ... 14:
        inputString += inChar;
        checksum += (uchar)inChar;
        rc++;
        break;
    case 15:
        inputString += inChar;
        rc++;
        break;
    default:
        checksum = 0;
        rc = 0;
        inputString = "";
        break;
    }
    // if the incoming character is a newline, set a flag
    // so the main loop can do something about it:
    if ( rc == 16 ) {
        //Serial.println("");
        //Serial.println(checksum, DEC);
        unsigned int sum_inv = 0xffff - checksum;
        //Serial.println("");
        //Serial.println(sum_inv, DEC);
        String s = decToHex( sum_inv, 4 );
        //Serial.println("");
        //Serial.println( s );
        unsigned int mychksum = hexToDec( s.substring(2) );
        //Serial.println("");
        //Serial.println( mychksum, DEC );
        //Serial.println( (uchar)inChar, DEC );
        if ( (uchar)inChar - mychksum == 0 ) {
            //Serial.println("");
            //Serial.println( mychksum, DEC );
            chksum_OK = true;
            checksum = 0;
        }
        rc = 0;
        inputString_copy = inputString;
        stringComplete = true;
        rc = 0;
        inputString = "";
        delay(10);
    } 
  }
}

unsigned int hexToDec(String hexString) {
  
  unsigned int decValue = 0;
  int nextInt;
  
  for (int i = 0; i < hexString.length(); i++) {
    
    nextInt = int(hexString.charAt(i));
    if (nextInt >= 48 && nextInt <= 57) nextInt = map(nextInt, 48, 57, 0, 9);
    if (nextInt >= 65 && nextInt <= 70) nextInt = map(nextInt, 65, 70, 10, 15);
    if (nextInt >= 97 && nextInt <= 102) nextInt = map(nextInt, 97, 102, 10, 15);
    nextInt = constrain(nextInt, 0, 15);
    
    decValue = (decValue * 16) + nextInt;
  }
  
  return decValue;
}

String decToHex(int decValue, byte desiredStringLength) {
    String hexString = String(decValue, HEX);
    while (hexString.length() < desiredStringLength) hexString = "0" + hexString;
    return hexString;
}

void clearAllState() {
    activate_code = 0x00;
    comstate = 0;
}

/*
* Function：Write_MFRC5200
* Description：write a byte data into one register of MR RC522
* Input parameter：addr--register address；val--the value that need to write in
* Return：Null
*/
void Write_MFRC522(uchar addr, uchar val)
{
	digitalWrite(chipSelectPin, LOW);

	//address format：0XXXXXX0
	SPI.transfer((addr<<1)&0x7E);	
	SPI.transfer(val);

	digitalWrite(chipSelectPin, HIGH);
}

/*
* Function：Read_MFRC522
* Description：read a byte data into one register of MR RC522
* Input parameter：addr--register address
* Return：return the read value
*/
uchar Read_MFRC522(uchar addr)
{
	uchar val;

	digitalWrite(chipSelectPin, LOW);

	//address format：1XXXXXX0
	SPI.transfer(((addr<<1)&0x7E) | 0x80);	
	val =SPI.transfer(0x00);

	digitalWrite(chipSelectPin, HIGH);

	return val;	
}

/*
* Function：SetBitMask
* Description：set RC522 register bit
* Input parameter：reg--register address;mask--value
* Return：null
*/
void SetBitMask(uchar reg, uchar mask)  
{
	uchar tmp;
	tmp = Read_MFRC522(reg);
	Write_MFRC522(reg, tmp | mask);  // set bit mask
}


/*
* Function：ClearBitMask
* Description：clear RC522 register bit
* Input parameter：reg--register address;mask--value
* Return：null
*/
void ClearBitMask(uchar reg, uchar mask)  
{
	uchar tmp;
	tmp = Read_MFRC522(reg);
	Write_MFRC522(reg, tmp & (~mask));  // clear bit mask
} 


/*
* Function：AntennaOn
* Description：Turn on antenna, every time turn on or shut down antenna need at least 1ms delay
* Input parameter：null
* Return：null
*/
void AntennaOn(void)
{
	uchar temp;

	temp = Read_MFRC522(TxControlReg);
	if (!(temp & 0x03))
	{
		SetBitMask(TxControlReg, 0x03);
	}
}


/*
* Function：AntennaOff
* Description：Turn off antenna, every time turn on or shut down antenna need at least 1ms delay
* Input parameter：null
* Return：null
*/
void AntennaOff(void)
{
	ClearBitMask(TxControlReg, 0x03);
}


/*
* Function：ResetMFRC522
* Description： reset RC522
* Input parameter：null
* Return：null
*/
void MFRC522_Reset(void)
{
	Write_MFRC522(CommandReg, PCD_RESETPHASE);
}


/*
* Function：InitMFRC522
* Description：initilize RC522
* Input parameter：null
* Return：null
*/
void MFRC522_Init(void)
{
	digitalWrite(NRSTPD,HIGH);

	MFRC522_Reset();

	//Timer: TPrescaler*TreloadVal/6.78MHz = 24ms
	Write_MFRC522(TModeReg, 0x8D);		//Tauto=1; f(Timer) = 6.78MHz/TPreScaler
	Write_MFRC522(TPrescalerReg, 0x3E);	//TModeReg[3..0] + TPrescalerReg
	Write_MFRC522(TReloadRegL, 30);           
	Write_MFRC522(TReloadRegH, 0);

	Write_MFRC522(TxAutoReg, 0x40);		//100%ASK
	Write_MFRC522(ModeReg, 0x3D);		//CRC initilizate value 0x6363	???

	//ClearBitMask(Status2Reg, 0x08);		//MFCrypto1On=0
	//Write_MFRC522(RxSelReg, 0x86);		//RxWait = RxSelReg[5..0]
	//Write_MFRC522(RFCfgReg, 0x7F);   		//RxGain = 48dB

	AntennaOn();		//turn on antenna
}


/*
* Function：MFRC522_Request
* Description：Searching card, read card type
* Input parameter：reqMode--search methods，
*			 TagType--return card types
*			 	0x4400 = Mifare_UltraLight
*				0x0400 = Mifare_One(S50)
*				0x0200 = Mifare_One(S70)
*				0x0800 = Mifare_Pro(X)
*				0x4403 = Mifare_DESFire
* return：return MI_OK if successed
*/
uchar MFRC522_Request(uchar reqMode, uchar *TagType)
{
	uchar status;  
	uint backBits;			//the data bits that received

	Write_MFRC522(BitFramingReg, 0x07);		//TxLastBists = BitFramingReg[2..0]	???

	TagType[0] = reqMode;
	status = MFRC522_ToCard(PCD_TRANSCEIVE, TagType, 1, TagType, &backBits);

	if ((status != MI_OK) || (backBits != 0x10))
	{    
		status = MI_ERR;
	}

	return status;
}


/*
* Function：MFRC522_ToCard
* Description：communicate between RC522 and ISO14443
* Input parameter：command--MF522 command bits
*			 sendData--send data to card via rc522
*			 sendLen--send data length		 
*			 backData--the return data from card
*			 backLen--the length of return data
* return：return MI_OK if successed
*/
uchar MFRC522_ToCard(uchar command, uchar *sendData, uchar sendLen, uchar *backData, uint *backLen)
{
	uchar status = MI_ERR;
	uchar irqEn = 0x00;
	uchar waitIRq = 0x00;
	uchar lastBits;
	uchar n;
	uint i;

	switch (command)
	{
		case PCD_AUTHENT:		//verify card password
		{
			irqEn = 0x12;
			waitIRq = 0x10;
			break;
		}
		case PCD_TRANSCEIVE:	//send data in the FIFO
		{
			irqEn = 0x77;
			waitIRq = 0x30;
			break;
		}
		default:
			break;
	}

	Write_MFRC522(CommIEnReg, irqEn|0x80);	//Allow interruption
	ClearBitMask(CommIrqReg, 0x80);			//Clear all the interrupt bits
	SetBitMask(FIFOLevelReg, 0x80);			//FlushBuffer=1, FIFO initilizate
	Write_MFRC522(CommandReg, PCD_IDLE);	//NO action;cancel current command	???

	//write data into FIFO
	for (i=0; i<sendLen; i++)
	{   
		Write_MFRC522(FIFODataReg, sendData[i]);    
	}

	//procceed it
	Write_MFRC522(CommandReg, command);
	if (command == PCD_TRANSCEIVE)
	{    
		SetBitMask(BitFramingReg, 0x80);		//StartSend=1,transmission of data starts  
	}   

	//waite receive data is finished
	i = 2000;	//i should adjust according the clock, the maxium the waiting time should be 25 ms???
	do 
	{
		//CommIrqReg[7..0]
		//Set1 TxIRq RxIRq IdleIRq HiAlerIRq LoAlertIRq ErrIRq TimerIRq
		n = Read_MFRC522(CommIrqReg);
		i--;
	}
	while ((i!=0) && !(n&0x01) && !(n&waitIRq));

	ClearBitMask(BitFramingReg, 0x80);			//StartSend=0

	if (i != 0)
	{    
		if(!(Read_MFRC522(ErrorReg) & 0x1B))	//BufferOvfl Collerr CRCErr ProtecolErr
		{
			status = MI_OK;
			if (n & irqEn & 0x01)
			{   
				status = MI_NOTAGERR;			//??   
			}

			if (command == PCD_TRANSCEIVE)
			{
				n = Read_MFRC522(FIFOLevelReg);
				lastBits = Read_MFRC522(ControlReg) & 0x07;
				if (lastBits)
				{   
					*backLen = (n-1)*8 + lastBits;   
				}
				else
				{   
					*backLen = n*8;   
				}

				if (n == 0)
				{   
					n = 1;    
				}
				if (n > MAX_LEN)
				{   
					n = MAX_LEN;   
				}

				//read the data from FIFO
				for (i=0; i<n; i++)
				{   
					backData[i] = Read_MFRC522(FIFODataReg);    
				}
			}
		}
		else
		{   
		status = MI_ERR;  
		}

	}
	//SetBitMask(ControlReg,0x80);           //timer stops
	//Write_MFRC522(CommandReg, PCD_IDLE); 
	return status;
}


/*
* Function：MFRC522_Anticoll
* Description：Prevent conflict, read the card serial number 
* Input parameter：serNum--return the 4 bytes card serial number, the 5th byte is recheck byte
* return：return MI_OK if successed
*/
uchar MFRC522_Anticoll(uchar *serNum)
{
	uchar status;
	uchar i;
	uchar serNumCheck=0;
	uint unLen;


	ClearBitMask(Status2Reg, 0x08);		//TempSensclear
	ClearBitMask(CollReg,0x80);			//ValuesAfterColl
	Write_MFRC522(BitFramingReg, 0x00);		//TxLastBists = BitFramingReg[2..0]

	serNum[0] = PICC_ANTICOLL;
	serNum[1] = 0x20;
	status = MFRC522_ToCard(PCD_TRANSCEIVE, serNum, 2, serNum, &unLen);

	if (status == MI_OK)
	{
		//Verify card serial number
		for (i=0; i<4; i++)
		{   
			serNumCheck ^= serNum[i];
		}
		if (serNumCheck != serNum[i])
		{   
			status = MI_ERR;    
		}
	}

	SetBitMask(CollReg, 0x80);		//ValuesAfterColl=1

	return status;
} 


/*
* Function：CalulateCRC
* Description：Use MF522 to caculate CRC
* Input parameter：pIndata--the CRC data need to be read，len--data length，pOutData-- the caculated result of CRC
* return：Null
*/
void CalulateCRC(uchar *pIndata, uchar len, uchar *pOutData)
{
	uchar i, n;

	ClearBitMask(DivIrqReg, 0x04);			//CRCIrq = 0
	SetBitMask(FIFOLevelReg, 0x80);			//Clear FIFO pointer
	//Write_MFRC522(CommandReg, PCD_IDLE);

	//Write data into FIFO	
	for (i=0; i<len; i++)
	{   
		Write_MFRC522(FIFODataReg, *(pIndata+i));   
	}
	Write_MFRC522(CommandReg, PCD_CALCCRC);

	//waite CRC caculation to finish
	i = 0xFF;
	do 
	{
		n = Read_MFRC522(DivIrqReg);
		i--;
	}
	while ((i!=0) && !(n&0x04));			//CRCIrq = 1

	//read CRC caculation result
	pOutData[0] = Read_MFRC522(CRCResultRegL);
	pOutData[1] = Read_MFRC522(CRCResultRegM);
}


/*
* Function：MFRC522_SelectTag
* Description：Select card, read card storage volume
* Input parameter：serNum--Send card serial number
* return：return the card storage volume
*/
uchar MFRC522_SelectTag(uchar *serNum)
{
	uchar i;
	uchar status;
	uchar size;
	uint recvBits;
	uchar buffer[9]; 

	//ClearBitMask(Status2Reg, 0x08);			//MFCrypto1On=0

	buffer[0] = PICC_SElECTTAG;
	buffer[1] = 0x70;
	for (i=0; i<5; i++)
	{
		buffer[i+2] = *(serNum+i);
	}
	CalulateCRC(buffer, 7, &buffer[7]);		//??
	status = MFRC522_ToCard(PCD_TRANSCEIVE, buffer, 9, buffer, &recvBits);

	if ((status == MI_OK) && (recvBits == 0x18))
	{   
		size = buffer[0]; 
	}
	else
	{   
		size = 0;    
	}

	return size;
}


/*
* Function：MFRC522_Auth
* Description：verify card password
* Input parameters：authMode--password verify mode
					0x60 = verify A passowrd key 
					0x61 = verify B passowrd key 
					BlockAddr--Block address
					Sectorkey--Block password
					serNum--Card serial number ，4 bytes
* return：return MI_OK if successed
*/
uchar MFRC522_Auth(uchar authMode, uchar BlockAddr, uchar *Sectorkey, uchar *serNum)
{
	uchar status;
	uint recvBits;
	uchar i;
	uchar buff[12]; 

	//Verify command + block address + buffer password + card SN
	buff[0] = authMode;
	buff[1] = BlockAddr;
	for (i=0; i<6; i++)
	{    
		buff[i+2] = *(Sectorkey+i);   
	}
	for (i=0; i<4; i++)
	{    
		buff[i+8] = *(serNum+i);   
	}
	status = MFRC522_ToCard(PCD_AUTHENT, buff, 12, buff, &recvBits);

	if ((status != MI_OK) || (!(Read_MFRC522(Status2Reg) & 0x08)))
	{   
		status = MI_ERR;   
	}

	return status;
}


/*
* Function：MFRC522_Read
* Description：Read data 
* Input parameters：blockAddr--block address;recvData--the block data which are read
* return：return MI_OK if successed
*/
uchar MFRC522_Read(uchar blockAddr, uchar *recvData)
{
	uchar status;
	uint unLen;

	recvData[0] = PICC_READ;
	recvData[1] = blockAddr;
	CalulateCRC(recvData,2, &recvData[2]);
	status = MFRC522_ToCard(PCD_TRANSCEIVE, recvData, 4, recvData, &unLen);

	if ((status != MI_OK) || (unLen != 0x90))
	{
		status = MI_ERR;
	}

	return status;
}


/*
* Function：MFRC522_Write
* Description：write block data
* Input parameters：blockAddr--block address;writeData--Write 16 bytes data into block
* return：return MI_OK if successed
*/
uchar MFRC522_Write(uchar blockAddr, uchar *writeData)
{
	uchar status;
	uint recvBits;
	uchar i;
	uchar buff[18]; 

	buff[0] = PICC_WRITE;
	buff[1] = blockAddr;
	CalulateCRC(buff, 2, &buff[2]);
	status = MFRC522_ToCard(PCD_TRANSCEIVE, buff, 4, buff, &recvBits);

	if ((status != MI_OK) || (recvBits != 4) || ((buff[0] & 0x0F) != 0x0A))
	{   
		status = MI_ERR;   
	}

	if (status == MI_OK)
	{
		for (i=0; i<16; i++)		//Write 16 bytes data into FIFO
		{    
			buff[i] = *(writeData+i);   
		}
		CalulateCRC(buff, 16, &buff[16]);
		status = MFRC522_ToCard(PCD_TRANSCEIVE, buff, 18, buff, &recvBits);

		if ((status != MI_OK) || (recvBits != 4) || ((buff[0] & 0x0F) != 0x0A))
		{   
			status = MI_ERR;   
		}
	}

	return status;
}


/*
* Function：MFRC522_Halt
* Description：Command the cards into sleep mode
* Input parameters：null
* return：null
*/
void MFRC522_Halt(void)
{
	uchar status;
	uint unLen;
	uchar buff[4]; 

	buff[0] = PICC_HALT;
	buff[1] = 0;
	CalulateCRC(buff, 2, &buff[2]);

	status = MFRC522_ToCard(PCD_TRANSCEIVE, buff, 4, buff,&unLen);
}
