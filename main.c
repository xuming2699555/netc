#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "cJSON.h"
#include "FWCConnect.h"

struct netconf
{
    char *name;
    char *inet;
    char *netmask;
};
struct rule
{
    char Rule[1024];
    struct rule *next;
};
struct chain
{
    char chainname[10];
    int polocy;
    struct rule *rule;
    struct chain *next;
};
struct table
{
    char *tablename;
    struct chain *chainlist;
};

char **split(const char *source, char flag)
{
    char **pt;
    int j, n = 0;
    int count = 1;
    int len = strlen(source);
    char tmp[len + 1];
    tmp[0] = '\0';

    for (int i = 0; i < len; ++i)
    {
        if (source[i] == flag && source[i + 1] == '\0')
            continue;
        else if (source[i] == flag && source[i + 1] != flag)
            count++;
    }
    // 多分配一个char*，是为了设置结束标志
    pt = (char **)malloc((count + 1) * sizeof(char *));

    count = 0;
    for (int i = 0; i < len; ++i)
    {
        if (i == len - 1 && source[i] != flag)
        {
            tmp[n++] = source[i];
            tmp[n] = '\0'; // 字符串末尾添加空字符
            j = strlen(tmp) + 1;
            pt[count] = (char *)malloc(j * sizeof(char));
            strcpy(pt[count++], tmp);
        }
        else if (source[i] == flag)
        {
            j = strlen(tmp);
            if (j != 0)
            {
                tmp[n] = '\0'; // 字符串末尾添加空字符
                pt[count] = (char *)malloc((j + 1) * sizeof(char));
                strcpy(pt[count++], tmp);
                // 重置tmp
                n = 0;
                tmp[0] = '\0';
            }
        }
        else
            tmp[n++] = source[i];
    }
    // 设置结束标志
    pt[count] = NULL;

    return pt;
}

int getTableData2(char *inputPath, char *outputPath, char *tableName)
{
    //TODO:参数合法性检查

    //创建表结构
    struct table newtable;
    newtable.tablename = (char *)malloc(32 * sizeof(char));
    strcpy(newtable.tablename, tableName);
    newtable.chainlist = NULL;
    struct chain *curchain = NULL;
    struct rule *currule = NULL;

    //处理输入文件
    FILE *infp = fopen(inputPath, "r");
    char linebuf[1024];
    if (infp == NULL)
    {
        printf("无法打开规则文件: %s\n", inputPath);
        return 1;
    }
    while (!feof(infp))
    {
        fgets(linebuf, 1024, infp);
        //链名行
        if (linebuf[0] == 'C' || linebuf[0] == 'c')
        {
            currule = NULL;
            //创建新链
            struct chain *chain = (struct chain *)malloc(sizeof(struct chain));
            //处理字符串，获取链名和默认策略
            char **p1;
            p1 = split(linebuf, ' ');
            for (int i = 0; p1[i] != NULL; i++)
            {
                if ((strcmp(p1[i], "Chain") == 0) || (strcmp(p1[i], "chain") == 0))
                {
                    strcpy(chain->chainname, p1[++i]);
                }
                else if (strcmp(p1[i] + 1, "policy") == 0)
                {
                    if (strchr(p1[++i], 'A') != NULL)
                    {
                        chain->polocy = 1;
                    }
                    else
                    {
                        chain->polocy = 0;
                    }
                }
            }
            if (newtable.chainlist == NULL)
            {
                newtable.chainlist = chain;
                curchain = chain;
            }
            else
            {
                curchain->next = chain;
                curchain = curchain->next;
            }
        }
        else if ((linebuf[0] == 'A') || (linebuf[0] == 'D') || (linebuf[0] == 'S'))
        {
            struct rule *newrule = (struct rule *)malloc(sizeof(struct rule));
            newrule->next = NULL;
            strcpy(newrule->Rule, linebuf);
            if (currule == NULL)
            {
                curchain->rule = newrule;
                currule = newrule;
            }
            else
            {
                currule->next = newrule;
                currule = currule->next;
            }
        }
    }
    fclose(infp);

    //生成结果数据
    FILE *outfp;
    curchain = newtable.chainlist;
    while (curchain != NULL)
    {
        char filepath[256];
        strcpy(filepath, outputPath);
        strcat(filepath, tableName);
        strcat(filepath, curchain->chainname);

        outfp = fopen(filepath, "w");
        if (outfp == NULL)
        {
            printf("创建结果文件失败： %s", filepath);
            continue;
        }
        fputs((curchain->polocy) ? "Accept\n" : "Deny\n", outfp);
        currule = curchain->rule;
        while (currule != NULL)
        {
            fputs(currule->Rule, outfp);
            currule = currule->next;
        }
        curchain = curchain->next;
    }

    return 0;
}

cJSON *struct_to_json(struct netconf *struct_obj)
{
    cJSON *json_nec = cJSON_CreateObject();
    cJSON_AddStringToObject(json_nec, "name", struct_obj->name);
    cJSON_AddStringToObject(json_nec, "inet", struct_obj->inet);
    cJSON_AddStringToObject(json_nec, "netmask", struct_obj->netmask);
    return json_nec;
}

int getNatData(char *inputPath, char *outputPath)
{
    FILE *fp;
    FILE *outfp;
    outfp = fopen(outputPath, "w");
    char line[1024];
    fp = fopen(inputPath, "r");
    if (fp == NULL)
    {
        printf("无法打开网络检测文件: %s\n", inputPath);
        return 0;
    }
    while (!feof(fp))
    {
        line[0] = '\0';
        fgets(line, 1024, fp); //处理一行
        struct netconf *newnc;
        if (line[0] > ' ')
        {
            newnc = (struct netconf *)malloc(sizeof(struct netconf));
            char name[20];
            int i = 0;
            while (line[i] != ':')
            {
                name[i] = line[i];
                i++;
            }
            name[i] = '\0';
            newnc->name = name;
            //处理下一行
            line[0] = '\0';
            fgets(line, 1024, fp);
            char inet[16];
            int j = 0;
            for (; j < 15; j++)
            {
                if (line[j + 13] == ' ')
                {
                    break;
                }

                inet[j] = line[j + 13];
            }
            inet[j] = '\0';
            newnc->inet = inet;
            char netmask[16];
            int k = 0;
            for (; k < 15; k++)
            {
                if (line[k + 38] == ' ' || line[k + 38] == '\n')
                {
                    break;
                }
                netmask[k] = line[k + 38];
            }
            netmask[k] = '\0';
            newnc->netmask = netmask;
            cJSON *cj = struct_to_json(newnc);
            //printf("%s\n", cJSON_Print(cj));
            fputs(cJSON_Print(cj), outfp);
            fputc('\n', outfp);
        }
        if (feof(fp))
        {
            break;
        }
    }
    fclose(fp);
}

int getTableData(char *inputPath, char *outputPath, char *tableName)
{
    // int len = strlen(inputPath);
    // if (inputPath[len - 1] != '/')
    // {
    //     char newpath[len + 1];
    //     strcpy(newpath, inputPath);
    //     strcat(newpath, "/");
    //     inputPath = newpath;
    // }

    FILE *fp;
    char line[1024];
    fp = fopen(inputPath, "r");
    struct table newtable; //当前表
    newtable.tablename = tableName;
    newtable.chainlist = NULL;
    if (fp == NULL)
    {
        printf("无法打开规则文件: %s\n", inputPath);
        return 0;
    }
    else
    {
        struct chain *chain;
        struct chain *ptr; //链指针
        struct rule *rptr; //规则指针
        int newchainmask = 0;
        while (!feof(fp))
        {
            //line[0] = '\0';
            fgets(line, 1024, fp); //处理一行
            if (line[0] == 'C')    //链名行
            {
                newchainmask = 1;
                rptr = NULL;
                chain = malloc(sizeof(struct chain));
                chain->rule = NULL;
                //获取链名和默认策略
                char *end = strchr(line + 6, ' ');
                char *ifaccept = strchr(end, 'A');
                end[0] = '\0';
                strcpy(chain->chainname, line + 6);
                if (ifaccept) //策略为accpet
                {
                    chain->polocy = 1;
                }
                else //策略为deny
                {
                    chain->polocy = 0;
                }
                if (newtable.chainlist == NULL)
                {
                    newtable.chainlist = chain;
                    ptr = chain;
                }
                else
                {
                    ptr->next = chain;
                    ptr = ptr->next;
                }
            }
            else if (line[0] == 't') //无用行
            {
                continue;
            }
            else if (line[0] == 'A' || line[0] == 'D') //读取到规则行
            {
                struct rule *newr = malloc(sizeof(struct rule));
                newr->next = NULL;
                strcpy(newr->Rule, line);
                if (newchainmask == 1)
                {
                    chain->rule = newr;
                    rptr = newr;
                    newchainmask = 0;
                }
                else
                {
                    rptr->next = newr;
                    rptr = newr;
                }
            }
            if (feof(fp))
            {
                break;
            }
        }
    }
    fclose(fp);
    //一个表构建完成。开始生成数据文件
    //文件名为表名+链名
    FILE *outfp;
    struct chain *pchain = newtable.chainlist;
    while (pchain != NULL)
    {
        char filepath[256];
        strcpy(filepath, outputPath);
        strcat(filepath, tableName);
        strcat(filepath, pchain->chainname);
        outfp = fopen(filepath, "w");
        if (outfp == NULL)
        {
            printf("创建结果文件失败：%s", filepath);
            continue;
        }
        fputs((pchain->polocy) ? "accept\n" : "deny\n", outfp);
        struct rule *prule = pchain->rule;
        while (prule != NULL)
        {
            fputs(prule->Rule, outfp);
            prule = prule->next;
        }
        pchain = pchain->next;
    }
    return 0;
}

int main(int argc, char const *argv[])
{
    //处理命令行参数
    //TODO

    int sock;
    char report_msg[50];
    FWC_client_init(&sock);
    sprintf(report_msg, "start checking.");
    FWC_progress_report(sock, 5, 0, report_msg);

    //网口检测模块
    //TODO
    sprintf(report_msg, "start NIC checking.");
    FWC_progress_report(sock, 6, 0, report_msg);
    system("ifconfig > netconfig.txt");
    getNatData("netconfig.txt", "./result/datanet.txt");
    sprintf(report_msg, "complete NIC checking.");
    FWC_progress_report(sock, 6, 20, report_msg);

    //iptables规则检测
    sprintf(report_msg, "start policies checking.");
    FWC_progress_report(sock, 6, 20, report_msg);
    system("sudo iptables -t filter -nL > filter.txt");
    //filter文件读取
    //读取方式：按行读取
    //初始chain为空，依次查找INPUT、FORWARD、OUTPUT三个链

    if (getTableData2("filter.txt", "./result/", "filter") != 0)
    {
        //出错
    }
    sprintf(report_msg, "complete polocies checking table filter");
    FWC_progress_report(sock, 6, 40, report_msg);
    system("sudo iptables -t nat -nL > nat.txt");
    if (getTableData2("nat.txt", "./result/", "nat") != 0)
    {
        //return 0;
    }
    sprintf(report_msg, "complete polocies checking table nat");
    FWC_progress_report(sock, 6, 60, report_msg);
    system("sudo iptables -t raw -nL > raw.txt");
    if (getTableData2("raw.txt", "./result/", "raw") != 0)
    {
    }
    sprintf(report_msg, "complete polocies checking table raw");
    FWC_progress_report(sock, 6, 80, report_msg);
    system("sudo iptables -t mangle -nL > mangle.txt");
    if (getTableData2("mangle.txt", "./result/", "mangle") != 0)
    {
    }
    sprintf(report_msg, "complete polocies checking table mangle");
    FWC_progress_report(sock, 6, 100, report_msg);
    return 0;
}
