/** 
* @file XdjaKeyApi.h
* @brief 安全卡通用接口
* @author xdja
* @version 1.0.0.1
* @date 20130608
*/

#ifndef _XDJA_KEY_API_H_
#define _XDJA_KEY_API_H_

#ifdef WIN32
#ifndef XDJAKEYAPI
#define XDJAKEYAPI __declspec(dllimport)
#endif
#else
#define XDJAKEYAPI
#endif
typedef void* XKF_HANDLE;

/************************************************************************/
/* 错误代码定义                                                          */
/************************************************************************/
#define XKR_BASE                         0//0x0003A000
#define XKR_OK                           0x00000000                     //成功
#define XKR_PWD_N                        XKR_BASE+N                     //口令错误,剩余N重试机会
#define XKR_NO_HANDLE                    XKR_BASE-1                     //指定的句柄不存在
#define XKR_IO_FAILED                    XKR_BASE-2                     //通过卡接口收发数据失败
#define XKR_BACK_LENGTH                  XKR_BASE-3                     //返回数据之长度错误
#define XKR_BACK_DATA                    XKR_BASE-4                     //返回数据错误
#define XKR_RESET_FAILED                 XKR_BASE-5                     //卡重置失败
#define XKR_NO_ROLE                      XKR_BASE-6                     //指定的角色不存在
#define XKR_DATAIN_SIZE                  XKR_BASE-7                     //输入数据的长度不合适
#define XKR_OUTBUF_SIZE                  XKR_BASE-8                     //指定的数据接收缓冲区大小不合适
#define XKR_INVALID_PARA                 XKR_BASE-9                     //接口参数错误
#define XKR_PASSWORD                     XKR_BASE-10                    //口令错误,剩余重试次数为0
#define XKR_EEPROM_WRITE                 XKR_BASE-11                    //EEPROM写入错误
#define XKR_PARAMETER                    XKR_BASE-12                    //COS指令参数错误
#define XKR_CMD_NOTMATCH_LINE            XKR_BASE-13                    //命令与线路保护不适应
#define XKR_CMD_NOTMATCH_FAT             XKR_BASE-14                    //命令与文件结构不相容
#define XKR_NO_POWER                     XKR_BASE-15                    //权限不够
#define XKR_KEY_LOCKED                   XKR_BASE-16                    //密钥被锁死
#define XKR_DATA_PARAMETER               XKR_BASE-18                    //数据域参数错误
#define XKR_APP_LOCKED                   XKR_BASE-19                    //应用锁定
#define XKR_FILE_NOT_EXIST               XKR_BASE-20                    //文件不存在
#define XKR_NO_FILE_SPACE                XKR_BASE-21                    //文件无足够空间
#define XKR_NOT_GET_RANDOM               XKR_BASE-22                    //未取随机数
#define XKR_FILE_EXIST                   XKR_BASE-23                    //文件已存在
#define XKR_FILE_CONTENT                 XKR_BASE-24                    //文件内容错误
#define XKR_WRONG_STATE                  XKR_BASE-25                    //错误的状态
#define XKR_CARD_LOCKED                  XKR_BASE-26                    //卡锁定
#define XKR_WRONG_LE                     XKR_BASE-27                    //Le错误
#define XKR_NO_THIS_CMD                  XKR_BASE-28                    //命令不存在
#define XKR_INVALID_DATA                 XKR_BASE-29                    //数据无效
#define XKR_WRONG_MAC                    XKR_BASE-30                    //MAC错误
#define XKR_KEYFILE_NOT_EXIST            XKR_BASE-31                    //密钥文件不存在
#define XKR_KEY_NOT_EXIST                XKR_BASE-32                    //密钥不存在
#define XKR_WRONG_KEY_TYPE               XKR_BASE-33                    //密钥类型不对
#define XKR_BAD_PUBKEY                   XKR_BASE-34                    //返回公钥内容格式不对
#define XKR_HASH_FAILED                  XKR_BASE-35                    //HASH运算失败
#define XKR_RSAPUBLIC_FAILED             XKR_BASE-36                    //RSA公钥运算失败
#define XKR_BAD_PRIKEY                   XKR_BASE-37                    //返回私钥内容格式不对
#define XKR_SIGN_CONFIRM                 XKR_BASE-38                    //等待用户签名确认
#define XKR_SIGN_CANCEL                  XKR_BASE-39                    //用户签名确认取消
#define XKR_CONDITION                    XKR_BASE-40                    //使用条件不满足
#define XKR_DECRYPT_FAIL                 XKR_BASE-41                    //解密失败
#define XKR_NOT_FIND_DATA                XKR_BASE-42                    //文件偏移地址超出，即未找到数据
#define XKR_DGI_NOT_SUPPORT              XKR_BASE-43                    //DGI不支持
#define XKR_DATA_NOCORRENT               XKR_BASE-44                    //安全报文数据对象不正确
#define XKR_EXAUTH_FAIL                  XKR_BASE-45                    //外部认证失败
#define XKR_RSA_NOT_FIND                 XKR_BASE-46                    //RSA密钥未找到
#define XKR_TLOCK_FAILD	                 XKR_BASE-47                    //创建事务锁失败
#define XKR_TLOCK_TIMEOUT                XKR_BASE-48                    //事务锁超时
#define XKR_BAD_CERT                     XKR_BASE-49                    //证书内容错误
#define XKR_SIGN_VERIFY                  XKR_BASE-50                    //签名验证失败
#define XKR_GETMOUNTPATH_FAILD           XKR_BASE-51                    //获取盘符/挂载路径失败
#define XKR_MALLOC_FALID                 XKR_BASE-95                    //内存申请失败
#define XKR_BUFFERISNULL                 XKR_BASE-96                    //内存为空
#define XKR_NO_KEY                       XKR_BASE-97                    //未插入安全卡
#define XKR_NOT_SUPPORT                  XKR_BASE-98                    //暂不支持
#define XKR_NOT_ACTIVATED                XKR_BASE-99                    //卡未激活,需先激活才能正常使用
#define XKR_UNKNOWN                      XKR_BASE-100                   //未知错误
/************************************************************************/
/* 类型结构定义                                                          */
/************************************************************************/

///安全卡类型(已知)  
typedef enum _CARD_TYPE
{
        CT_ALL          =0x0000,
        CT_USBKEY       =0x0100,    //USBKEY	              0100
          CT_USBDEV       =0x0110,    //带驱动的USB设备  
          CT_NET          =0x0120,    //Win32 NET设备,用于ActiveX访问USBKEY。
// 		  CT_USB_AISINO   =0x0130,    //Aision芯片的USBKEY  
 		  CT_USB_CCORE    =0x0140,    //国芯芯片无存储USBKEY
// 		  CT_USB_CCORE_V2 =0X0150，   //国芯芯片带存储USBKEY
		  CT_USBCD        =0x0160,    //国芯芯片无存储USBKEY CDROM
		  CT_USBKEY30     =0x0170,    //华芯芯片带存储USBKEY
        CT_TF           =0x0200,    //TF
          CT_TF_XDJA      =0x0210,      //XDJATF卡
			CT_TF_XDJA_V1    =0x0211,        //XDJA多文件卡
			CT_TF_XDJA_V2    =0x0212,        //XDJA单文件卡
			CT_XDJA_CHIP  =0x0213,        //Android SD接口芯片
			CT_TF_XDJA_CUSTOM=0x0214,        //XDJA自定义文件卡
			CT_ACE           =0x0215,        //Win32   ACE手机
			CT_XDJA_SPI   =0x0217,        //Android SPI接口芯片
          CT_TF_INCOMM    =0x0220,      //INCOMM卡
            CT_TF_ZTEIC_OLD =0x0221,         //INCOMM低速卡1.0  0221
            CT_TF_ZTEIC_NEW =0x0222,         //INCOMM低速卡2.0  0222
            CT_TF_INCOMM_V1 =0x0223,         //INCOMM多文件，高功耗  0223
            CT_TF_INCOMM_V2 =0x0224,         //INCOMM多文件，低功耗  0224 
            CT_TF_INCOMM_EX =0x0225,         //INCOMM单文件卡        0225 
          CT_TF_RDFOX     =0x0230,      //REDFOX卡            0230
            CT_TF_REDFOX_LOW=0x0231,         //REDFOX低速卡     0231
            CT_TF_REDFOX_HIGH=0x0232,        //REDFOX高速卡     0232
        CT_TIC          =0x0300,    //双界面IC卡            0300
       // CT_NET          =0x0400,    //                      0400
        CT_IOS          =0x0500,    //                      0500  
}CARD_TYPE;
#define  CT_TF_XDJA_CHIP CT_XDJA_CHIP
#define  CT_TF_XDJA_SPI  CT_XDJA_SPI

///设备信息
typedef struct _DEVINFO
{
        unsigned char cardid[33];          //硬件编号,一般为长度32字节的字符串
        unsigned char cosver[65];          //COS版本号,不超过64字节的字符串
        CARD_TYPE cardtype;                //卡类型
        int  reserve;
}DEVINFO,*PDEVINFO;
//口令有效长度范围
#define PIN_MAX_LEN  16 //口令最大长度
#define PIN_MIN_LEN  6  //口令最小长度
#define FILE_ID_LEN  2  //
#define KEY_LEN_MAX  32
#define DIR_NAME_LEN 8 //目录名字最大字符数
///目录类型
enum DIR_TYPE
{
    ROOT_DIR=1,//根目录
    APP_DIR=2  //应用目录 
};
///目录结构
typedef struct _XDJA_DIR
{	
        unsigned char       id[FILE_ID_LEN];           //目录ID    应用目录时有效
        unsigned char       type;                      //根目录、应用目录  
        unsigned short      room;                      //空间大小 当应用目录时有效，最大16K
        unsigned char       create_Acl;                //创建权限的最低权限 
        unsigned char       delete_Acl;                //删除权限
        unsigned char       key_Acl;                   //添加对称密钥、解锁口令密钥最低权限
        unsigned char       name[DIR_NAME_LEN];        //目录名称
}XDJA_DIR,*PXDJA_DIR;
///文件类型 
enum FILE_TYPE
{
        FILE_BINARY= 1,  //二进制文件
        FILE_PUBLIC= 2,  //公钥文件
        FILE_PRIVATE=3   //私钥文件 
};
///文件结构
typedef struct _XDJA_FILE
{	
	    unsigned char       id[FILE_ID_LEN];    //文件ID
        unsigned char       type;               //文件类型
        unsigned short      room;               //空间大小  文件类型为二进制文件时有效
        unsigned char       read_Acl;           //读取权限  对rsa私钥文件 该值无效，卡的私钥不允许读取
        unsigned char       write_Acl;          //写入权限
        unsigned char       use_Acl;            //使用权限 当为公私钥文件时有效
}XDJA_FILE,*PXDJA_FILE;
///SM1密钥结构
typedef struct  _XDJAKEY_ATTR
{   
        unsigned char  id;                      //密钥 ID
        unsigned char  type;                    //密钥类型 sm1加密密钥 sm1解密密钥 解锁口令密钥
        unsigned char  use_Acl ;                //使用权限 sm1加密密钥 sm1解密密钥时有效
        unsigned char  update_Acl;              //更改权限
        unsigned char  key[KEY_LEN_MAX];        //密钥值 有效密钥长度根据密钥类型决定 sm1为16字节，解锁口令密钥有效长度为  PIN_MIN_LEN<=len<=PIN_MAX_LEN
        unsigned char  new_state;               //后续状态,新增

//以下三个当类型为解锁口令密钥时有效
        unsigned char  try_num;                 //尝试次数  
        unsigned char  unlock_role;             //解锁密钥可以解锁的role
        unsigned char  len;                     //密钥长度  有效长度同口令长度
}XDJAKEY_ATTR,*PXDJAKEY_ATTR;
///密钥类型
#define KEY_SM1_ENCRYPT         0x01 //SM1加密密钥
#define KEY_SM1_DECRYPT	        0x02 //SM1解密密钥
#define KEY_PIN_UNLOCK          0x03 //解锁口令 
#define KEY_PIN_ROLE            0x04 //角色口令 
#define KEY_SM1_RELOAD          0x05 //SM1口令重装密钥 
#define KEY_DES_RELOAD          0x06 //3DES口令重装密钥

///对称算法操作类型 加密 解密
#define OP_DECRYPT  0x00
#define OP_ENCRYPT  0x01
///对称算法操作模式  ECB  CBC
#define ECB_MODE    0x00
#define CBC_MODE    0x10
///对称算法模式类型标识
#define ECB_DECRYPT 0x00
#define ECB_ENCRYPT 0x01
#define CBC_DECRYPT 0x10
#define CBC_ENCRYPT 0x11
//临时密钥算法标识
typedef enum 
{
	TMP_ALG_SM1 = 0,
	TMP_ALG_DES = 1,
	TMP_ALG_3DES = 2,
	TMP_ALG_SM4 = 3
}TMP_ALG;
///卡中RSA运算的长度
#define CARD_RSA_LEN            128            
#define CARD_PRIME_LEN          64
#define MAX_RSA_MODULUS_BITS    2048
#define MAX_CARD_RSA_LEN        256
#define MIN_CARD_PRIME_LEN      128
///RSA公钥结构
typedef struct _XDJA_RSA_PUB_KEY
{
        unsigned int  bits;               //公钥模数长度，1024或2048
        unsigned char m[MAX_CARD_RSA_LEN];
        unsigned int  e;
}XDJA_RSA_PUB_KEY,*PXDJA_RSA_PUB_KEY;
///RSA私钥结构
typedef struct _XDJA_RSA_PRI_KEY {
        unsigned int bits;                //公钥模数长度
        unsigned char p[MIN_CARD_PRIME_LEN]; 
        unsigned char q[MIN_CARD_PRIME_LEN];
        unsigned char dp[MIN_CARD_PRIME_LEN];
        unsigned char dq[MIN_CARD_PRIME_LEN];
        unsigned char ce[MIN_CARD_PRIME_LEN];
} XDJA_RSA_PRI_KEY,*PXDJA_RSA_PRI_KEY;
#define KEY_LEN_SM2       32
///SM2曲线参数
typedef struct _XDJA_SM2_PARAM {
        unsigned char p[KEY_LEN_SM2];    //素数p
        unsigned char a[KEY_LEN_SM2];    //系数a
        unsigned char b[KEY_LEN_SM2];    //系数b
        unsigned char n[KEY_LEN_SM2];    //阶
        unsigned char x[KEY_LEN_SM2];    //基点G的x坐标
        unsigned char y[KEY_LEN_SM2];    //基点G的y坐标
} XDJA_SM2_PARAM,*PXDJA_SM2_PARAM;
///sm2私钥结构
typedef struct _XDJA_SM2_PRIKEY{
        unsigned char d[KEY_LEN_SM2];
}XDJA_SM2_PRIKEY, *PXDJA_SM2_PRIKEY;
///sm2公钥结构
typedef struct _XDJA_SM2_PUBKEY{
        unsigned char x[KEY_LEN_SM2];
        unsigned char y[KEY_LEN_SM2];
}XDJA_SM2_PUBKEY, *PXDJA_SM2_PUBKEY;

//每种角色对应一个权限,角色通过认证口令获得,可以认为角色就是权限
//#define ROLE_NUM         5 //权限数量
#define ROLE_A           1     //权限1
#define ROLE_B           2
#define ROLE_C           3
#define ROLE_D           4     //权限4
#define ROLE_E           5     //权限5
#define ROLE_Q           0x11  //权限4

#define SM2_KEY_GENERATE_DICT_SEND 0   //SM2协商密钥发起方
#define SM2_KEY_GENERATE_DICT_RECV 1   //SM2协商密钥响应方
#define SM2_UID_MAX     64             //签名时用户ID的最大长度
#define SM2_BLOCK_MAX   158            //SM2加密时明文的最大长度

//签名数据类型
typedef enum
{
	SIGN_HASH = 0,
	SIGN_NOHASH = 1
}SIGN_DATA_TYPE;
///USB分区
typedef enum
{
        USB_NORMAL_ZONE,  //普通区
        USB_SECU_ZONE,    //加密区
        USB_HEDD_ZONE,    //
        USB_INNOSTOR_ZONE //高速盘分区
}USB_FLASH_TYPE;
///USB FLASH读写模式
typedef enum 
{
        USB_READ_TEMP,
        USB_WRITE_TEMP,
        USB_READ_FOREVER,
        USB_WRITE_FORERVER,
        INNOSTOR_WRITE_TEMP
}USB_FLASH_RW_MODE;

#ifdef __cplusplus
extern "C" {
#endif

/**
* @brief 获取卡库版本
* 
* @param[out] version   卡库版本
* @param[in,out] verLen 长度
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_GetVersion(unsigned char * version, int * verLen);

/**
* @brief 获取卡库编译日期时间
* 
* @param[out] datatime 编译日期时间,格式data=mm:dd:yyyy,time=hh:mm:ss
* @param[in,out] len   返回长度
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_GetDateTime(unsigned char * datatime, int * len);

/************************************************************************/
/* 设备管理类接口                                                       */
/************************************************************************/

/**
* @brief 枚举设备
* 
* @param[in]  devType  枚举的设备类型，可选参数：CT_ALL,CT_USBKEY, CT_USBKEY30, CT_TF,CT_TF_XDJA_CHIP  
* @param[out] devNum   枚举到的设备个数，XKF_OpenDev索引从0开始
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_EnumDev(int devType, int * DevNum);
/**
* @brief 通过设备索引打开设备，返回设备句柄
* 说明：需要先枚举设备
*
* @param[in]   index   设备索引,从0开始,上限是枚举到的设备数
* @param[out]  hHandle 设备句柄
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_OpenDev(int index, XKF_HANDLE * hHandle);
/**
* @brief 打开指定设备,返回设备句柄
*  说明：无需枚举设备
*
* @param[in]   devName TF卡挂载路径,约定已'/'结束,如 /mnt/sdcard/, j:/
                       USB设备名称,如 /dev/sdd  //./PHYSICALDRIVE4
* @param[out]  hHandle 设备句柄
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_OpenDevByName(const unsigned char * devName, XKF_HANDLE * hHandle);
/**
* @brief 打开指定设备,返回设备句柄(仅支持ACE设备)
*  说明：需要枚举设备
*
* @param[in]   sn ACE设备序列号
* @param[out]  hHandle 设备句柄
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_OpenDevBySN(const char* sn, XKF_HANDLE * hHandle);
/**
* @brief 根据应用程序的包名,返回设备句柄(只用于Android4.4以上)
*
* @param[in]   packagePath 根据应用程序的包名，通过getPackageName()获取
* @param[out]  hHandle 设备句柄
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_OpenDevByNameEx(const char* packagePath, XKF_HANDLE * hHandle);
/**
* @brief 关闭设备
*
* @param[in] hHandle 设备句柄
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_CloseDev(XKF_HANDLE hHandle);
/**
* @brief  获得设备独占使用权（开启事务锁）
* 超时时间20秒
* 应用程序在函数组合或事务操作前通过该接口获取设备独占使用权，结束后必须立即释放独占权
*
* @param[in] hHandle 设备句柄
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_LockDev(XKF_HANDLE hHandle);
/**
* @brief  释放设备独占使用权（结束事务锁）
*
* @param[in] hHandle 设备句柄
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_UnlockDev(XKF_HANDLE hHandle);
/**
* @brief 设备命令传输
*
* @param[in]  hHandle 设备句柄
* @param[in]  pCmd    设备命令（APDU指令）
* @param[in]  cmdLen  命令长度
* @param[out] outBuf  返回结果数据
* @param[out] outlen  输入表示结果数据缓冲大小，输出表示结果数据实际长度
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_Transmit(XKF_HANDLE hHandle,unsigned char * pCmd,int cmdLen, unsigned char* outBuf, unsigned int * outlen);
/**
* @brief 设备命令传输
*
* @param[in]  hHandle 设备句柄
* @param[in]  pCmd    设备命令（APDU指令）
* @param[in]  cmdLen  命令长度
* @param[out] outBuf  返回包含状态码的结果数据
* @param[out] outlen  输入表示结果数据缓冲大小，输出表示结果数据实际长度
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_TransmitEx(XKF_HANDLE hHandle,unsigned char * pCmd,int cmdLen, unsigned char* outBuf, unsigned int * outlen);
/**
* @brief 获取设备信息，包括卡ID、COS版本、卡类型等（CT_USBKEY CT_USBKEY30 CT_TF CT_TF_XDJA_CHIP等）
*
* @param[in] hHandle 设备句柄
* @param[out] pDevInfo 返回设备信息
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_GetDevInfo(XKF_HANDLE hHandle,DEVINFO * pDevInfo);
/**
* @brief 设置卡驱动日志保存路径
*
* @param[in] logPath 日志保存路径
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_SetLogPath(const char* logPath);
/**
* @brief 启用Socket设备
*
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_EnableSocket();
/*
* @brief 激活芯片设备
* 
* @param[in] hHandle 设备句柄
* @param[in] param   激活因子
* @param[in] len     激活因子长度(一般为256字节)
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_ActivateCard(XKF_HANDLE hHandle,unsigned char* param, unsigned int len);
/**
* @brief 获取芯片激活状态
*
* @param[in] hHandle 设备句柄
*
* @retval XKR_OK              已经激活
* @retval XKR_NOT_ACTIVATED   未激活
*/
XDJAKEYAPI int XKF_GetActivateState(XKF_HANDLE hHandle);

/************************************************************************/
/*访问控制类接口                                                         */
/************************************************************************/

/**
* @brief 修改PIN
*
* @param[in] hHandle 设备句柄
* @param[in] pinRole PIN码角色
* @param[in] oldpin  旧PIN码
* @param[in] oldlen  旧PIN码长度
* @param[in] newpin  新PIN码
* @param[in] newlen  新PIN码长度
*
* @return 错误码
* @retval XKR_OK          成功
* @retval XKR_PWD_N       正数,剩余重试次数
* @retval XKR_PASSWORD    密码错误,剩余重试次数0
* @retval XKR_KEY_LOCKED  密钥被锁死
*/
XDJAKEYAPI int XKF_ChangePIN(XKF_HANDLE hHandle,int pinRole,const unsigned char* oldpin,int oldlen,const unsigned char* newpin,int newlen);
/**
* @brief 获取PIN码信息
*
* @param[in] hHandle 设备句柄
* @param[in] pinRole PIN码角色
*
* @return 重试次数或错误码
* @retval XKR_PWD_N       正数,剩余重试次数
* @retval XKR_PASSWORD    剩余重试次数0（已锁死）
*/
XDJAKEYAPI int XKF_GetPinTryCount(XKF_HANDLE hHandle,int pinRole);
/**
* @brief 校验PIN
*  用于口令验证以获得某种安全状态
*
* @param[in] hHandle 设备句柄
* @param[in] pinRole PIN码角色 
* @param[in] pin     PIN码
* @param[in] pinlen  PIN码长度
*
* @return 错误码
* @retval XKR_OK          成功
* @retval XKR_PWD_N       正数,剩余重试次数
* @retval XKR_PASSWORD    密码错误,剩余重试次数0
* @retval XKR_KEY_LOCKED  密钥被锁死
*/
XDJAKEYAPI int XKF_VerifyPIN(XKF_HANDLE hHandle,int pinRole,const unsigned char* pin,int pinlen);
/**
* @brief 解锁PIN
*
* @param[in] hHandle 设备句柄
* @param[in] id      解锁密钥ID 
* @param[in] key     解锁码
* @param[in] keylen  解锁码长度
* @param[in] newpin  新PIN码
* @param[in] newlen  新PIN码长度
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_UnlockPIN(XKF_HANDLE hHandle,int id,const unsigned char* key,int keylen,const unsigned char* newpin,int newlen);
/**
* @brief 重装PIN
*
* @param[in] hHandle 设备句柄
* @param[in] pinRole PIN码角色 
* @param[in] key     PIN码重装码
* @param[in] keylen  重装码长度
* @param[in] newpin  新PIN码
* @param[in] newlen  新PIN码长度
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_ReloadPIN(XKF_HANDLE hHandle,int pinRole,const unsigned char* key,int keylen,const unsigned char* newpin,int newlen);
/**
* @brief 卡重置，清除安全状态
*
* @param[in] hHandle 设备句柄
*
* @return 错误码
* @retval XKR_OK 成功
*/ 
XDJAKEYAPI int XKF_CardReset(XKF_HANDLE hHandle);
/**
* @brief 外部认证，认证通过后获取密钥对应的权限
*  过程：卡内取随机数，经外部SM1加密，再将密文送入卡内做外部认证（解密并比较）
*  要求：外部SM1加密密钥和卡内外部认证密钥相同
*
* @param[in] hHandle     设备句柄
* @param[in] exterAuthID 外部认证密钥ID
* @param[in] encRandom   16字节的随机数密文，经外部SM1加密
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_ExternalAuth(XKF_HANDLE hHandle, unsigned char exterAuthID, const unsigned char *encRandom);
/**
* @brief 内部认证（等同于SM1加密）
*  过程： 卡外产生随机数, 并送入卡内做内部认证运算, 将密文返回; 再由卡外解密并比较
*
* @param[in]  hHandle  设备句柄
* @param[in]  pDataIn  外部传入数据 
* @param[in]  dataLen  外部传入数据长度(16的整数倍)
* @param[in]  flag     指示加解密模式,ECB_DECRYPT、ECB_ENCRYPT、CBC_DECRYPT、CBC_ENCRYPT。
* @param[in]  kID      密钥标识ID(仅限0、SM1加密密钥、SM1解密密钥和内部认证密钥四种情况)
*                      当KID为0时, 表示临时密钥做内部认证运算；当kID不为零时, 表示所使用的密钥识号（密钥仅限SM1加密密钥、SM1解密密钥和内部认证密钥）
* @param[in]  tmpKey   临时密钥   当kID=0时,tmpKey有效
* @param[out] pDataOut SM1运算结果
* @param[in,out]  pIV  输入iv输出iv 在CBC时有效
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_InternalAuth(XKF_HANDLE hHandle,const unsigned char *pDataIn, int dataLen, int flag, unsigned char kID,const unsigned char *tmpKey, unsigned char *pDataOut, unsigned char *pIV);

/************************************************************************/
/*文件管理类接口                                                         */
/************************************************************************/

/**
* @brief 创建目录
* 条件:创建应用目录时，具有当前目录下，创建目录的权限
* 创建根目录时，当前卡文件系统必须为空。
*
* @param[in] hHandle 设备句柄
* @param[in] pDir    目录属性结构
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_CreateDir(XKF_HANDLE hHandle,PXDJA_DIR pDir);
/**
* @brief 获取当前目录剩余容量
*
* @param[in]  hHandle 设备句柄
* @param[out] size    剩余容量,单位字节Byte
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_GetDirSize(XKF_HANDLE hHandle,unsigned int * size);
/**
* @brief 创建文件
* 条件:具有当前目录下，创建文件的权限
*
* @param[in] hHandle 设备句柄
* @param[in] pFile   文件属性结构
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_CreateFile(XKF_HANDLE hHandle,PXDJA_FILE pFile);
/**
* @brief 通过ID选择文件或目录
* 按文件标识符选择，选择当前目录下基本文件或子目录文件。
* 在任何情况下均可通过标识符3F00选择MF
*
* @param[in] hHandle 设备句柄
* @param[in] fid     文件或目录id
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_SelectFile(XKF_HANDLE hHandle,const unsigned char* fid);
/**
* @brief 通过目录名选择目录
* 用目录名称选择，选择MF，或当前目录本身，或目录的下级子目录。
*
* @param[in] hHandle 设备句柄
* @param[in] name    目录名
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_SelectApp(XKF_HANDLE hHandle, const unsigned char * name);

/**
* @brief 删除文件
*
* @param[in] hHandle 设备句柄
* @param[in] fid     文件ID，全0表示删除目录下所有文件
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_DeleteFile(XKF_HANDLE hHandle,const unsigned char* fid);
/**
* @brief 取文件属性
*
* @param[in] hHandle 设备句柄
* @param[in] fid     文件ID
* @param[out] pFile  文件属性，仅文件类型和文件大小有效
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_GetFileInfo(XKF_HANDLE hHandle,const unsigned char* fid,PXDJA_FILE pFile);
/**
* @brief 读文件
* 条件：具有读该文件的权限
*
* @param[in] hHandle 设备句柄
* @param[in] fid     文件ID 
* @param[in] readPos 起始位置
* @param[in] readLen 要读取的长度
* @param[out] pDataout 读取内容缓冲区
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_ReadFile(XKF_HANDLE hHandle,const unsigned char* fid,int readPos, int readLen,unsigned char * pDataout);
/**
* @brief 写文件
* 条件：具有写该文件的权限
*
* @param[in] hHandle 设备句柄
* @param[in] fid     文件ID 
* @param[in] readPos 起始位置
* @param[in] readLen 写入内容的长度
* @param[out] pDataout 写入内容
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_WriteFile(XKF_HANDLE hHandle,const unsigned char* fid,int writePos, int writeLen, const unsigned char * pDatain);
/**
* @brief 读RSA公钥
* 条件：具有读RSA公钥的权限
*
* @param[in] hHandle 设备句柄
* @param[in] fid     文件ID 
* @param[out] pPub    RSA公钥
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_ReadRsaPubKey(XKF_HANDLE hHandle, const unsigned char * fid, PXDJA_RSA_PUB_KEY pPub);
/**
* @brief 写RSA公钥
* 条件：具有写RSA公钥的权限
*
* @param[in] hHandle 设备句柄
* @param[in] fid     文件ID 
* @param[in] pPub    RSA公钥
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_WriteRsaPubKey(XKF_HANDLE hHandle, const unsigned char * fid, PXDJA_RSA_PUB_KEY pPub);
/**
* @brief 写RSA私钥
* 条件：具有写RSA私钥的权限
*
* @param[in] hHandle 设备句柄
* @param[in] fid     文件ID 
* @param[in] pPri    RSA私钥
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_WriteRsaPriKey(XKF_HANDLE hHandle, const unsigned char * fid, PXDJA_RSA_PRI_KEY pPri);
/**
* @brief 读sm2公钥
* 条件：具有读sm2公钥的权限
*
* @param[in] hHandle 设备句柄
* @param[in] fid     文件ID 
* @param[out] pPub    sm2公钥
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_ReadSm2PubKey(XKF_HANDLE hHandle, const unsigned char * fid, PXDJA_SM2_PUBKEY pPub);
/**
* @brief 写sm2公钥
* 条件：具有写sm2公钥的权限
*
* @param[in] hHandle 设备句柄
* @param[in] fid     文件ID 
* @param[in] pPub    sm2公钥
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_WriteSm2PubKey(XKF_HANDLE hHandle, const unsigned char * fid, PXDJA_SM2_PUBKEY pPub);
/**
* @brief 写sm2私钥
* 条件：具有写sm2私钥的权限
*
* @param[in] hHandle 设备句柄
* @param[in] fid     文件ID 
* @param[in] pPri    sm2私钥
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_WriteSm2PriKey(XKF_HANDLE hHandle, const unsigned char * fid, PXDJA_SM2_PRIKEY pPri);
/**
* @brief 读证书
* 条件：具有读证书的权限
*
* @param[in] hHandle   设备句柄
* @param[in] fid       证书文件ID 
* @param[out] certBuf  证书信息
* @param[out] certLen  证书信息长度
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_ReadCert(XKF_HANDLE hHandle, const unsigned char * fid, unsigned char *certBuf, int* certLen);
/**
* @brief 写证书
* 条件：具有写证书的权限
*
* @param[in] hHandle   设备句柄
* @param[in] fid       证书文件ID 
* @param[in] certBuf   证书信息(DER编码)
* @param[in] certLen   证书信息长度
*
* @return 错误码
* @retval XKR_OK              成功
* @retval XKR_NO_POWER        权限不够
* @retval XKR_FILE_NOT_EXIST  文件不存在
*/
XDJAKEYAPI int XKF_WriteCert(XKF_HANDLE hHandle, const unsigned char * fid, const unsigned char *certBuf, int certLen);

/************************************************************************/
/*密码服务类接口                                                         */
/************************************************************************/

/**
* @brief 卡内产生随机数
*
* @param[in] hHandle 设备句柄
* @param[in] len     需要获取的随机数长度
* @param[out] Random 输出的随机数缓冲区
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_GenRandom(XKF_HANDLE hHandle,unsigned int len, unsigned char* pRandom);
/**
* @brief 创建SM1密钥）
* 条件:具有当前目录下，增加密钥的权限
*
* @param[in] hHandle 设备句柄
* @param[in] pAttr   SM1密钥属性结构
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_CreateKey(XKF_HANDLE hHandle,PXDJAKEY_ATTR pKey);
/**
* @brief 导入SM1密钥
* 条件：具有更新该密钥的权限
*
* @param[in] hHandle 设备句柄
* @param[in] type    导入方式(4bit) 和 导入密钥类型(4bit)。本版本支持明文导入。
* @param[in] pDataIn 密钥数据。密钥长度由密钥类型自动决定。在本版本中，SM1密钥为16字节
* @param[in] kID 密钥ID
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_ImportKey(XKF_HANDLE hHandle,unsigned int type,const unsigned char * pDatain,unsigned char kID);
/**
* @brief SM1加解密运算（硬算法），使用卡内密钥
*
* @param[in]  hHandle  设备句柄
* @param[in]  pDataIn  被运算的数据 
* @param[in]  dataLen  输入数据长度
* @param[in]  flag     指示加密、解密与运算模式。
* @param[out] pDataOut SM1运算结果
* @param[in]  kID      密钥ID
* @param[in,out]  pIV  输入iv输出iv 在CBC时有效
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_SM1(XKF_HANDLE hHandle,const unsigned char *pDataIn,int dataLen,int flag,unsigned char *pDataOut ,unsigned char kID,unsigned char* pIV);
/**
* @brief 导入临时SM1密钥
*
* @param[in] hHandle 设备句柄
* @param[in] tmpkey  SM1密钥 16字节
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_ImportTmpKey(XKF_HANDLE hHandle, const unsigned char *tmpkey);
/**
* @brief 导入临时对称密钥
*
* @param[in] hHandle 设备句柄
* @param[in] tmpkey  密钥 des 8字节,其他16字节
* @param[in] alg     临时密钥算法: 0 sm1 ,1 des, 2 3des , 3 sm4
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_ImportCipherKey(XKF_HANDLE hHandle, const unsigned char *tmpkey, TMP_ALG alg);
/**
* @brief SM1加解密（硬算法），使用临时SM1密钥
*
* @param[in]  hHandle  设备句柄
* @param[in]  pDataIn  被运算的数据。
* @param[in]  dataLen  输入数据长度。
* @param[in]  flag     指示加密、解密与运算模式。
* @param[out] pDataOut SM1运算结果。
* @param[in]  pIV      输入iv输出iv 在CBC时有效
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_TmpSM1(XKF_HANDLE hHandle,const unsigned char *pDataIn,int dataLen,int flag,unsigned char *pDataOut,unsigned char* pIV);
/**
* @brief 对称加解密（硬算法），使用临时对称密钥 （算法由导入密钥时确定）
*
* @param[in]  hHandle  设备句柄
* @param[in]  pDataIn  被运算的数据。
* @param[in]  dataLen  输入数据长度。
* @param[in]  alg      临时密钥算法。
* @param[in]  flag     指示加密、解密与运算模式。
* @param[out] pDataOut 运算结果。
* @param[in]  pIV      输入iv输出iv 在CBC时有效
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_TmpCipher(XKF_HANDLE hHandle,const unsigned char *pDataIn,int dataLen, TMP_ALG alg, int flag,unsigned char *pDataOut,unsigned char* pIV);
/**
* @brief SM1加解密（硬算法），卡外送入密钥
*
* @param[in] hHandle  设备句柄
* @param[in] tmpkey   SM1密钥 16字节	
* @param[in] pDataIn  被运算的数据。
* @param[in] dataLen  输入数据长度。
* @param[in] flag     指示加密、解密与运算模式。
* @param[out] pDataOut SM1运算结果。
* @param[in] pIV      输入iv输出iv 在CBC时有效
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_SM1KEY(XKF_HANDLE hHandle, const unsigned char *tmpkey, const unsigned char *pDataIn, int dataLen, int flag, unsigned char *pDataOut, unsigned char *pIV);

/**
* @brief SSF33加解密（硬算法），卡外送入密钥 (分组长度16)
*
* @param[in] hHandle    设备句柄
* @param[in] tmpkey     密钥，16字节
* @param[in] pDataIn    输入数据，数据长度为16整数倍
* @param[in] dataLen    输入数据长度
* @param[in] flag       指示加密、解密与运算模式。
* @param[out] pDataOut  输出数据
* @param[in] pIV        采用EBC模式此参数无效，可置为NULL;CBC模式时为初始向量，16字节
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_SSF33(XKF_HANDLE hHandle, const unsigned char *tmpkey, const unsigned char *pDataIn, int dataLen, int flag, unsigned char *pDataOut, unsigned char *pIV);
/**
* @brief 卡外SM4加解密（软算法），卡外送入密钥 (分组长度16)
*
* @param[in] hHandle    设备句柄
* @param[in] tmpkey     密钥，16字节
* @param[in] pDataIn    输入数据，数据长度为16整数倍
* @param[in] dataLen    输入数据长度
* @param[in] flag       指示加密、解密与运算模式。
* @param[out] pDataOut  输出数据
* @param[in] pIV        采用EBC模式此参数无效，可置为NULL;CBC模式时为初始向量，16字节
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_SM4KEY(XKF_HANDLE hHandle, const unsigned char *tmpkey, const unsigned char *pDataIn, int dataLen, int flag, unsigned char *pDataOut, unsigned char *pIV);
/**
* @brief 卡内SM4加解密（硬算法），卡外送入密钥 (分组长度16)
*
* @param[in] hHandle    设备句柄
* @param[in] tmpkey     密钥，16字节
* @param[in] pDataIn    输入数据，数据长度为16整数倍
* @param[in] dataLen    输入数据长度
* @param[in] flag       指示加密、解密与运算模式。
* @param[out] pDataOut  输出数据
* @param[in] pIV        采用EBC模式此参数无效，可置为NULL;CBC模式时为初始向量，16字节
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_SM4KEYEx(XKF_HANDLE hHandle, const unsigned char *tmpkey, const unsigned char *pDataIn, int dataLen, int flag, unsigned char *pDataOut, unsigned char *pIV);
/**
* @brief SM6加解密（硬算法），卡外送入密钥 (分组长度16)
*（SCB2）
*
* @param[in] hHandle    设备句柄
* @param[in] tmpkey     密钥，32字节
* @param[in] pDataIn    输入数据，数据长度为16整数倍
* @param[in] dataLen    输入数据长度
* @param[in] flag       指示加密、解密与运算模式。
* @param[out] pDataOut  输出数
* @param[in] pIV        采用EBC模式此参数无效，可置为NULL;CBC模式时为初始向量，16字节
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_SM6KEY(XKF_HANDLE hHandle, const unsigned char *tmpkey, const unsigned char *pDataIn, int dataLen, int flag, unsigned char *pDataOut, unsigned char *pIV);
/**
* @brief DES加解密（软算法），卡外送入密钥 (分组长度8)
*
* @param[in] hHandle    设备句柄
* @param[in] tmpkey     密钥，8字节
* @param[in] pDataIn    输入数据，数据长度为8整数倍
* @param[in] dataLen    输入数据长度
* @param[in] flag       指示加密、解密与运算模式。
* @param[out] pDataOut  输出数据
* @param[in] pIV        采用EBC模式此参数无效，可置为NULL;CBC模式时为初始向量，8字节
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_DESKEY(XKF_HANDLE hHandle, const unsigned char *tmpkey, const unsigned char *pDataIn, int dataLen, int flag, unsigned char *pDataOut, unsigned char *pIV);
/**
* @brief 3DES加解密（软算法），卡外送入密钥 (分组长度8)
*
* @param[in] hHandle    设备句柄
* @param[in] tmpkey     密钥，16字节或24字节
* @param[in] keylen     密钥长度 （16 24）
* @param[in] pDataIn    输入数据，数据长度为8整数倍
* @param[in] dataLen    输入数据长度
* @param[in] flag       指示加密、解密与运算模式。
* @param[out] pDataOut  输出数据
* @param[in] pIV        采用EBC模式此参数无效，可置为NULL;CBC模式时为初始向量，8字节
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_DES3KEY(XKF_HANDLE hHandle, const unsigned char *tmpkey, int keylen, const unsigned char *pDataIn, int dataLen, int flag, unsigned char *pDataOut, unsigned char *pIV);

/**
* @brief AES加解密（软算法），卡外送入密钥 (分组长度16)
*
* @param[in] hHandle    设备句柄
* @param[in] tmpkey     密钥，16字节、24字节或32字节 （128位、192位或256位）
* @param[in] keylen     密钥长度 （16 24 32）
* @param[in] pDataIn    输入数据，数据长度为16整数倍
* @param[in] dataLen    输入数据长度
* @param[in] flag       指示加密、解密与运算模式。
* @param[out] pDataOut  输出数据
* @param[in] pIV        采用EBC模式此参数无效，可置为NULL;CBC模式时为初始向量，16字节
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_AESKEY(XKF_HANDLE hHandle, const unsigned char *tmpkey, int keylen, const unsigned char *pDataIn, int dataLen, int flag, unsigned char *pDataOut, unsigned char *pIV);
/**
* @brief 卡内产生RSA密钥对
* 条件：密钥对不出卡时要求有写指定公私钥文件的权限
*
* @param[in] hHandle 设备句柄
* @param[in] bits    RSA公钥模数长度，1024或2048
* @param[in] pubfid  公钥文件ID，为0x00 0x00时表示公钥导出卡外
* @param[in] prifid  私钥文件ID，公私钥文件ID均为0x00 0x00时私钥可导出卡外
* @param[in] pPub    RSA公钥结构，公钥文件ID为0x00 0x00时有效
* @param[in] pPri    RSA私钥结构，公私钥文件ID均为0x00 0x00时有效
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_GenRSAKeyPair(XKF_HANDLE hHandle,int bits,const unsigned char * pubfid, const unsigned char* prifid, PXDJA_RSA_PUB_KEY pPub,PXDJA_RSA_PRI_KEY pPri);
/**
* @brief SHA1运算(软算法)
*
* @param[in] hHandle  设备句柄
* @param[in] pDataIn  输入数据
* @param[in] dataLen    输入数据长度
* @param[out]  pDataOut 输出运算结果 20个字节
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_SHA1(XKF_HANDLE hHandle,const unsigned char *pDataIn,int dataLen,unsigned char *pDataOut);
/**
* @brief SHA1运算(硬算法)
*
* @param[in] hHandle  设备句柄
* @param[in] pDataIn  输入数据
* @param[in] dataLen    输入数据长度
* @param[out]  pDataOut 输出运算结果 20个字节
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_SHA1Ex(XKF_HANDLE hHandle, const unsigned char *pDataIn,int dataLen,unsigned char *pDataOut);
/**
* @brief SM3运算(软算法)
*
* @param[in] hHandle   设备句柄
* @param[in] pDataIn   输入数据
* @param[in] dataLen   输入数据长度
* @param[out] pDataOut 输出运算结果 32字节
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_SM3(XKF_HANDLE hHandle, const unsigned char *pDatain, int dataLen, unsigned char *pDataOut);
/**
* @brief SM3运算（硬算法）
*
* @param[in] hHandle   设备句柄
* @param[in] pDataIn   输入数据
* @param[in] dataLen   输入数据长度
* @param[out] pDataOut 输出运算结果 32字节
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_SM3Ex(XKF_HANDLE hHandle, const unsigned char *pDatain, int dataLen, unsigned char *pDataOut);

/**
* @brief RSA公钥运算 （RSA签名验证）
* 传入数据填充或解填充由调用者进行
*
* @param[in]  hHandle   设备句柄
* @param[in]  fid       RSA公钥文件ID,为0x00 0x00时使用外部公钥
* @param[in]  pPub      RSA公钥结构，公钥文件ID为0x00 0x00时有效
* @param[in]  pDataIn   输入数据
* @param[in]  dlen      输入数据长度，RSA1024为128，RSA2048为256
* @param[out] pDataOut  输出数据
* @param[out] outLen    输出结果长度，128或256
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_RSAPubKeyCalc(XKF_HANDLE hHandle, const unsigned char *fid,PXDJA_RSA_PUB_KEY pPub, const unsigned char *pDataIn,int dlen,unsigned char * pDataOut,unsigned int *outLen);
/**
* @brief RSA私钥运算 （RSA签名）
* 传入数据由调用者进行填充。
*
* @param[in] hHandle  设备句柄
* @param[in] fid       私钥ID
* @param[in] pDataIn   输入数据
* @param[in] dlen      输入数据长度，RSA1024为128，RSA2048为256
* @param[out] pDataOut 输出数据
* @param[out] outLen   输出结果长度，128或256
*
* @return 错误码
* @retval XKR_OK        成功
* @retval XKR_NO_POWER  权限不够
*/
XDJAKEYAPI int XKF_RSAPriKeyCalc(XKF_HANDLE hHandle,const unsigned char *fid, const unsigned char *pDataIn,int dlen,unsigned char* pDataOut, unsigned int *outLen);
/**
* @brief RSA私钥运算 （RSA签名）
* 传入数据由调用者进行填充。
*
* @param[in] hHandle   设备句柄
* @param[in] pin	   pin码
* @param[in] pinlen	   pin密码	
* @param[in] pinrole   pin角色	
* @param[in] fid       私钥ID
* @param[in] pDataIn   输入数据
* @param[in] dlen      输入数据长度，RSA1024为128，RSA2048为256(暂不支持)
* @param[out] pDataOut 输出数据
* @param[out] outLen   输出结果长度，128或256
*
* @return 错误码
* @retval XKR_OK        成功
* @retval XKR_NO_POWER  权限不够
*/
XDJAKEYAPI int XKF_RSAPriKeyCalcEx(XKF_HANDLE hHandle,unsigned char* pin,int pinlen,int pinrole, const unsigned char *fid, const unsigned char *pDataIn,int dlen,unsigned char* pDataOut, unsigned int *outLen);
/**
* @brief RSA数据签名
*
* @param[in] hHandle         设备句柄
* @param[in] bits            RSA公钥模数 
* @param[in] prikeyid        私钥ID  
* @param[in] datatype        数数据类型SIGN_DATA_TYPE
* @param[in] pDatain         数据
* @param[in] dlen            摘要数据数据长度必须为20；输入数据长度
* @param[out] signData       输出签名数据
* @param[out] outlen         输出数据长度 128或256
*
* @return 错误码
* @retval XKR_OK        成功
* @retval XKR_NO_POWER  权限不够
*/
XDJAKEYAPI int XKF_RSASign(XKF_HANDLE hHandle, int bits, const unsigned char *prikeyid, int datatype, const unsigned char *pDatain, int dlen, unsigned char *signData,unsigned int *outlen);
/**
* @brief RSA数据签名验证
*
* @param[in] hHandle         设备句柄
* @param[in] bits            RSA公钥模数 
* @param[in] pubkeyid        公钥ID
* @param[in] rsaPubkey       签名用公钥，当pubkeyid为0x00 0x00时使用
* @param[in] datatype        数据类型SIGN_DATA_TYPE
* @param[in] pDatain         输入数据
* @param[in] dlen            摘要数据长度必须为20
* @param[in] signData	     验签数据
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_RSASignVerify(XKF_HANDLE hHandle, int bits, const unsigned char *pubkeyid, PXDJA_RSA_PUB_KEY rsaPubkey, int datatype, const unsigned char *pDatain,unsigned int dlen, unsigned char *signData);

/**
* @brief 产生信封
* 产生16字节的随机数作为会话密钥，用P1P2指定的公钥加密，将加密结果送出卡外，同时保存随机数在临时密钥区域。
*
* @param[in] hHandle         设备句柄
* @param[in] pubkeyid        公钥文件ID
* @param[in] pPubkey         外部公钥,当公钥文件ID为全0时有效
* @param[in] alg             会话密钥算法,取值1、2、3、4分别表示SM1、DES、3DES、SM4
* @param[out] pDataout       信封数据
* @param[out] outlen         信封数据长度
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_PackEnvelope(XKF_HANDLE hHandle,const unsigned char * pubfid, PXDJA_RSA_PUB_KEY pPubkey, int alg, unsigned char *pDataout,unsigned int * outlen);
/**
* @brief 拆信封
* 将送入的数据用P1P2指定的私钥进行解密，将解密后的结果保存在临时区域。
*
* @param[in] hHandle         设备句柄
* @param[in] prikeyid        私钥文件ID
* @param[in] alg             会话密钥算法,取值1、2、3、4分别表示SM1、DES、3DES、SM4
* @param[in] pDataIn         信封数据
* @param[in] dlen            信封数据长度
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_UnpackEnvelope(XKF_HANDLE hHandle,const unsigned char * prifid,int alg,unsigned char * pDataIn,int dlen);

/**
* @brief SM1密钥分散
* 密钥分散只能对SM1加密密钥或者SM1解密密钥进行。其功能是将卡外送入的密钥因子用指定的密钥进行加密，并将加密结果存入临时区域。
*
* @param[in] hHandle  设备句柄
* @param[in] keyId    用于密钥分散的主密钥、SM1加密秘钥、解密秘钥
* @param[in] KeyParam 分散因子
* @param[in] paramLen 分散因子长度,不能超过16 
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_KeyDisperse(XKF_HANDLE hHandle,int keyId, unsigned char * keyParam, unsigned int paramLen);

/**
* @brief 设置SM2算法身份标识
*
* @param[in] hHandle  设备句柄
* @param[in] sm2id    身份标识
* @param[in] dlen     身份标识长度
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_SetSM2Id(XKF_HANDLE hHandle, const unsigned char *sm2id, int dlen);
/**
* @brief 获取SM2算法身份标识
*
* @param[in]  hHandle   设备句柄
* @param[out] sm2id     身份标识
* @param[out] outlen    身份标识长度
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_GetSM2Id(XKF_HANDLE hHandle, unsigned char *sm2id,unsigned int *outlen );
/**
* @brief 设置SM2算法参数
*
* @param[in] hHandle      设备句柄
* @param[in] sm2param     参数结构体指针
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_SetSM2Param(XKF_HANDLE hHandle,PXDJA_SM2_PARAM sm2param);
/**
* @brief 取得SM2算法参数
*
* @param[in] hHandle     设备句柄
* @param[out] sm2param   参数结构体指针
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_GetSM2Param(XKF_HANDLE hHandle,PXDJA_SM2_PARAM sm2param);
/**
* @brief 生成SM2密钥对
*
* @param[in] hHandle         设备句柄
* @param[in] pubkeyid        公钥文件ID,为0x00 0x00时表示公钥导出卡外
* @param[in] prikeyid        私钥文件ID,公私钥ID均为0x00 0x00时表示私钥导出卡外
* @param[out] sm2pubkey      SM2公钥结构，公钥文件ID为0x00 0x00时有效
* @param[out] sm2prikey      SM2私钥结构，公私钥文件ID均为0x00 0x00时有效
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_GenSM2KeyPair(XKF_HANDLE hHandle, const unsigned char *pubkeyid, const unsigned char *prikeyid, PXDJA_SM2_PUBKEY sm2pubkey, PXDJA_SM2_PRIKEY sm2prikey);
/**
* @brief SM2公钥加密
*  XDJA密文结构： 0x04 | x(32B) | y(32B) | 密文 | 明文HASH(32B)
*
* @param[in] hHandle         设备句柄
* @param[in] pubkeyid        SM2公钥ID，两字节，第二个字节有效 ，为0x00 0x00表示公钥随数据传入
* @param[in] sm2pubkey       公钥,当pubkeyid为0x00 0x00时有效
* @param[in] pDatain         明文数据,最大长度不超过158
* @param[in] dlen            数据长度
* @param[out] pDataout       加密后密文,缓冲长度至少为dlen+97
* @param[out] outlen         加密后数据长度
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_SM2Encrypt(XKF_HANDLE hHandle, const unsigned char *pubkeyid, PXDJA_SM2_PUBKEY sm2pubkey, const unsigned char *pDatain, int dlen, unsigned char *pDataout,unsigned int *outLen);
/*
* @brief SM2公钥加密（国密标准）
* 国密密文结构：  x(32B) | y(32B) | 明文HASH(32B) | 密文长度(4B) | 密文
*
* @param[in] hHandle         设备句柄
* @param[in] pubkeyid        SM2公钥ID，两字节，第二个字节有效 ，为0x00 0x00表示公钥随数据传入
* @param[in] sm2pubkey       公钥,当pubkeyid为0x00 0x00时有效
* @param[in] pDatain         明文数据,最大长度不超过155
* @param[in] dlen            数据长度
* @param[out] pDataout       加密后密文,缓冲长度至少为dlen+100
* @param[out] outlen         加密后数据长度
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_SM2Encrypt_GM(XKF_HANDLE hHandle, const unsigned char *pubkeyid, PXDJA_SM2_PUBKEY sm2pubkey, const unsigned char *pDatain, int dlen, unsigned char *pDataout,unsigned int *outLen);
/**
* @brief SM2私钥解密
*
* @param[in] hHandle         设备句柄
* @param[in] prikeyid        SM2私钥ID 两字节，第二个字节有效
* @param[in] pDatain         密文数据,最大长度不超过SM2_BLOCK_MAX+97
* @param[in] dlen            数据长度
* @param[out] pDataout       解密后的明文数据,缓冲区至少为dlen-97
* @param[out] outlen         解密后数据长度
*
* @return 错误码
* @retval XKR_OK        成功
* @retval XKR_NO_POWER  权限不够
*/
XDJAKEYAPI int XKF_SM2Decrypt(XKF_HANDLE hHandle, const unsigned char *prikeyid, const unsigned char *pDatain, int dlen, unsigned char *pDataout,unsigned int *outlen);
/**
* @brief SM2私钥解密（国密标准）
*
* @param[in] hHandle         设备句柄
* @param[in] prikeyid        SM2私钥ID 两字节，第二个字节有效
* @param[in] pDatain         密文数据,最大长度不超过255
* @param[in] dlen            数据长度
* @param[out] pDataout       解密后的明文数据,缓冲区至少为dlen-100
* @param[out] outlen         解密后数据长度
*
* @return 错误码
* @retval XKR_OK        成功
* @retval XKR_NO_POWER  权限不够
*/
XDJAKEYAPI int XKF_SM2Decrypt_GM(XKF_HANDLE hHandle, const unsigned char *prikeyid, const unsigned char *pDatain, int dlen, unsigned char *pDataout,unsigned int *outlen);
/**
* @brief SM2数据签名（软HASH）
* 如果待签名数据已经SM3HASH，直接签名；否则先进行SM3HASH（软算法）
*
* @param[in] hHandle         设备句柄
* @param[in] pubkeyid        公钥ID,当datatype=1时,pubkeyid有效
* @param[in] prikeyid        私钥ID 
* @param[in] datatype        数据类型SIGN_DATA_TYPE
* @param[in] pDatain         输入数据
* @param[in] dlen            数据长度,如果是摘要数据长度必须为32
* @param[out] signData       输出签名数据,缓冲区长度必须大于64字节
* @param[out] outlen         输出数据长度
*
* @return 错误码
* @retval XKR_NO_POWER  权限不够
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_SM2Sign(XKF_HANDLE hHandle, const unsigned char *pubkeyid, const unsigned char *prikeyid,int datatype,const unsigned char *pDatain, int dlen, unsigned char *signData,unsigned int *outlen);
/**
* @brief SM2数据签名（硬HASH）
* 先对待签名数据进行SM3HASH(硬算法)，再签名
*
* @param[in] hHandle         设备句柄
* @param[in] pubkeyid        公钥ID,当datatype=1时,pubkeyid有效
* @param[in] prikeyid        私钥ID 
* @param[in] pDatain         待签名数据
* @param[in] dlen            待签名数据长度
* @param[out] signData       输出签名数据,缓冲区长度必须大于64字节
* @param[out] outlen         输出数据长度
*
* @return 错误码
* @retval XKR_NO_POWER  权限不够
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_SM2SignEx(XKF_HANDLE hHandle, const unsigned char *pubkeyid, const unsigned char *prikeyid,const unsigned char *pDatain, int dlen, unsigned char *signData,unsigned int *outlen);

/**
* @brief SM2数据签名验证（软HASH）
* 如果待签名数据已经SM3HASH，直接验签；否则先进行SM3HASH（软算法）
*
* @param[in] hHandle         设备句柄
* @param[in] pubkeyid        公钥ID
* @param[in] datatype        数据类型SIGN_DATA_TYPE
* @param[in] sm2pubkey       签名用公钥，当pubkeyid为0x00 0x00时使用
* @param[in] pDatain         数据
* @param[in] dlen            数据长度，如果是摘要数据长度必须为32
* @param[in] signData        验签数据
*
* @return 错误码
* @retval XKR_OK        成功
*/
XDJAKEYAPI int XKF_SM2SignVerify(XKF_HANDLE hHandle, const unsigned char *pubkeyid, int datatype, PXDJA_SM2_PUBKEY sm2pubkey, const unsigned char *pDatain, int dlen, unsigned char *signData);
/**
* @brief SM2数据签名验证（硬HASH）
* 先对待签名数据进行SM3HASH（硬算法），再验签
*
* @param[in] hHandle         设备句柄
* @param[in] pubkeyid        公钥ID
* @param[in] sm2pubkey       签名用公钥，当pubkeyid为0x00 0x00时使用
* @param[in] pDatain         待签名数据
* @param[in] dlen            待签名数据长度
* @param[in] signData        验签数据
*
* @return 错误码
* @retval XKR_OK        成功
*/
XDJAKEYAPI int XKF_SM2SignVerifyEx(XKF_HANDLE hHandle, const unsigned char *pubkeyid, PXDJA_SM2_PUBKEY sm2pubkey, const unsigned char *pDatain, int dlen, unsigned char *signData);

/**
* @brief SM2协商密钥初始化
*
* @param[in] hHandle          设备句柄
* @param[in] pubkeyid         SM2公钥ID 两字节,第二个字节有效,第一字节必须为0x00
* @param[out] pdataout        产生协商数据
* @param[out] outlen          输出数据长度
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_SM2KeyGenInit(XKF_HANDLE hHandle, const unsigned char *pubkeyid, unsigned char *pdataout,unsigned int *outlen);
/**
* @brief SM2协商密钥 计算步骤
*
* @param[in] hHandle          设备句柄
* @param[in] pubkeyid         SM2公钥ID 两字节,第一节字必须为0x00,第二个字节有效 当dictflag=SM2_KEY_GENERATE_DICT_SEND 时 公钥ID为0x000x00
* @param[in] prikeyid         SM2私钥ID 两字节,第一节字必须为0x00,第二个字节有效
* @param[in] pDatain          输入数据
*								当dictflag=SM2_KEY_GENERATE_DICT_SEND 时，输入数据为 响应方的ID（TLV格式）||响应方公钥x坐标（TLV格式）||响应方公钥y坐标（TLV格式）||响应方临时公钥x坐标（TLV格式）||响应方临时公钥y坐标(TLV格式)
*								当dictflag=SM2_KEY_GENERATE_DICT_RECV 时，输入数据为 发起方的ID（TLV格式）||发起方公钥x坐标（TLV格式）||发起方公钥y坐标（TLV格式）||发起方临时公钥x坐标（TLV格式）||发起方临时公钥y坐标(TLV格式)
* @param[in] dlen             输入数据长度 
* @param[out] pDataout        产生协商数据
* @param[out] outlen          输出数据长度
* @param[in] dictflag         发起对象,SM2_KEY_GENERATE_DICT_SEND为发起方,SM2_KEY_GENERATE_DICT_RECV为响应方]
* @param[in] prikeyflag       密钥存储标记 1固定位置,0临时位置  
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_SM2KeyGenCompute(XKF_HANDLE hHandle, const unsigned char *pubkeyid, const unsigned char *prikeyid, const unsigned char *pDatain, int dlen, unsigned char *pDataout,unsigned int *outlen, unsigned char dictflag, unsigned char keyflag);
/**
* @brief SM2协商密钥验证
*
* @param[in] hHandle         设备句柄
* @param[in] pDatain         输入数据
* @param[in] dlen            输入数据长度 固定32字节
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_SM2KeyGenVerify(XKF_HANDLE hHandle, const unsigned char *pDatain, int dlen);

/************************************************************************/
/*TF卡专用接口                                                        */
/************************************************************************/
/**
* @brief 获取TF卡设备挂载路径
*
* @param[in] hHandle    设备句柄
* @param[out] mountpath 挂载路径  win32下获取盘符   Linux下获取挂载路径  
* @param[out] pathlen   路径长度
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_GetTFMountPath(XKF_HANDLE hHandle, char* mountpath,int * pathlen);
/**
* @brief 获取隐藏分区容量
*
* @param[in] hHandle 设备句柄
* @param[out] size   返回隐藏分区扇区数量
* 
* @return 错误码
* @retval 0 成功
*/
XDJAKEYAPI int XKF_GetTFZoneSize(XKF_HANDLE handle,int* size);
/**
* @brief 读TF卡内隐藏扇区,数据大小为字节
*
* @param[in]     hHandle      设备句柄
* @param[in]     sectorStart  扇区号
* @param[out]	 pDataBuf     数据缓冲区
* @param[in]     buffSize     数据大小
*
* @return 错误码
* @retval 0 成功
*/
XDJAKEYAPI int XKF_ReadTFZone(XKF_HANDLE handle,int sectorStart, unsigned char *pDataBuf, int buffSize);
/**
* @brief 写TF卡内隐藏扇区,数据大小为字节
* @param[in]     hHandle      设备句柄
* @param[in]     sectorStart  扇区号
* @param[in]	 pDataBuf     数据缓冲区
* @param[in]     buffSize    数据大小
*
* @return 错误码
* @retval 0 成功
*/
XDJAKEYAPI int XKF_WriteTFZone(XKF_HANDLE handle,int sectorStart, unsigned char *pDataBuf, int buffSize);

/************************************************************************/
/*加密U盘专用接口                                                        */
/************************************************************************/

/**
* @brief 获取加密U盘指定分区的挂载路径
*
* @param[in] hHandle 设备句柄
* @param[in] type    分区类型，含普通区、加密区、高速盘分区三种
* @param[out] path   返回该分区的挂载路径
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_GetUsbMountPath(XKF_HANDLE hHandle,USB_FLASH_TYPE type,unsigned char* path);
/**
* @brief 修改加密U盘FLASH读写模式
*
* @param[in] hHandle 设备句柄
* @param[in] mode    新的读写模式：普通区临时可写、临时只读、永久可写、永久只读，高速盘临时可写 共五种
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_SetUsbRWMode(XKF_HANDLE hHandle,USB_FLASH_RW_MODE mode);
/**
* @brief 读加密U盘普通区扇区
*
* @param[in] hHandle 设备句柄
* @param[in] addr    扇区起始地址
* @param[in] secs    扇区数量
* @param[out] pdata  数据接收缓冲区
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_ReadUsbNormalSecs(XKF_HANDLE hHandle,int addr,short secs,unsigned char* pdata);
/**
* @brief 写加密U盘普通区扇区
*
* @param[in] hHandle 设备句柄
* @param[in] addr    扇区起始地址
* @param[in] secs    扇区数量
* @param[in] pdata  待写数据缓冲区
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_WriteUsbNormalSecs(XKF_HANDLE hHandle,int addr,short secs, unsigned char* pdata);
/**
* @brief 打开加密U盘加密区
*
* @param[in] hHandle 设备句柄
* @param[in] pass    口令
* @param[in] passlen 口令长度
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_OpenUsbSecuZone(XKF_HANDLE hHandle, const unsigned char* pass,int passlen);
/**
* @brief 关闭加密U盘加密区
*
* @param[in] hHandle 设备句柄
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_CloseUsbSecuZone(XKF_HANDLE hHandle);
/**
* @brief 修改加密U盘加密区口令
* 注：如果旧口令不正确，卡内部就会较少一次旧口令的重试次数。修改口令可以被认为是认证旧口令、修改新口令的联合操作。
*
* @param[in] hHandle 设备句柄
* @param[in] oldpass 旧口令
* @param[in] oldlen  旧口令长度
* @param[in] newpass 新口令
* @param[in] newlen  新口令长度
* @param[in] type    口令类型：1加密盘口令； 2加密盘解锁口令
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_ChgUsbSecuZonePin(XKF_HANDLE hHandle,const unsigned char* oldpass,int oldlen, const unsigned char* newpass,int newlen,int type);
/**
* @brief 解锁加密盘口令
* 条件：要求输入正确的加密盘解锁口令
*
* @param[in] hHandle 设备句柄
* @param[in] key     解锁口令
* @param[in] keyLen  解锁口令长度
* @param[in] pin     新的口令
* @param[in] pinLen  新口令的长度
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_UnlockUsbSecuZone(XKF_HANDLE hHandle,const unsigned char *key,int keyLen, const unsigned char *pin,int pinLen);
/**
* @brief 初始化加密U盘隐藏区
*
* @param[in] hHandle 设备句柄
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_InitUsbHiddZone(XKF_HANDLE hHandle);
/**
* @brief 获取加密U盘隐藏扇区大小
*
* @param[in]  hHandle 设备句柄
* @param[out] hdSize  返回大小
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_GetUsbHiddZoneSize(XKF_HANDLE hHandle,unsigned int * hdSize);
/**
* @brief 读加密U盘隐藏扇区
*
* @param[in] hHandle     设备句柄
* @param[in] dwStartAddr 起始扇区地址
* @param[out] pOutBuff    读缓冲
* @param[in] buffSize    要读取的长度
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_ReadUsbHiddZone(XKF_HANDLE hHandle,unsigned int dwStartAddr,void* pOutBuff,unsigned int buffSize);
/**
* @brief 写加密U盘隐藏扇区
*
* @param[in] hHandle     设备句柄
* @param[in] dwStartAddr 起始扇区地址
* @param[in] pOutBuff    写缓冲
* @param[in] buffSize    要写入长度
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_WriteUsbHiddZone(XKF_HANDLE hHandle,unsigned int dwStartAddr,void * pInBuff,unsigned int buffSize);
/**
* @brief 发送USB SCSI指令
*
* @param[in] hHandle     设备句柄
* @param[in] pCDBbuff    CDB
* @param[in] cdbLength   CDB长度
* @param[in] sendDataBuf 发送数据缓冲
* @param[in] sendDataLen 发送数据长度
* @param[out] recvDataBuf 接收数据缓冲
* @param[out] recvDataLen 接收数据长度
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_ExecUsbScsiCmd(XKF_HANDLE hHandle,void* pCDBbuff,unsigned int cdbLength,void* sendDataBuf,unsigned int sendDataLen,void * recvDataBuf,unsigned int * recvDataLen);
/***********************************************************************/
/*二代U盾专用接口                                                       */
/***********************************************************************/

/**
* @brief 判断设备是否二代U盾
*
* @param[in] hHandle 设备句柄
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_Is2gKey(XKF_HANDLE hHandle);
/**
* @brief 二代盾签名
*
* @param[in] hHandle   设备句柄
* @param[in] prikeyid  私钥ID
* @param[in] pDatain   签名数据
* @param[in] dlen      签名数据长度
* @param[in] pDatain   签名结果
* @param[in] dlen      签名结果长度
* @param[in] dataType  签名数据类型
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_2gKeySign(XKF_HANDLE hHandle,const unsigned char * prikeyid, const unsigned char * pDatain,int dlen, unsigned char *pDataout, unsigned int *outlen, int dataType);
/**
* @brief 获取2代盾剩余电量
*
* @param[in] hHandle 设备句柄
* @param[out] state  充电状态:  1表示未充电, 0表示正在充电
* @param[out] power  返回值为百分比值,例如返回10表示剩余10%的电量
*
* @return 错误码
* @retval XKR_OK 成功
*/
XDJAKEYAPI int XKF_GetRemainPower(XKF_HANDLE hHandle,int * state, int * power);

#ifdef __cplusplus
}
#endif

#endif

