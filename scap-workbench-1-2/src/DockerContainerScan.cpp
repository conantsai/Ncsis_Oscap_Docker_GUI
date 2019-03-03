#include "DockerContainerScan.h"
#include "ui_DockerContainerScan.h"
#include "stdlib.h"
#include <iostream>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <regex>
#include <QLabel>
#include <QtGui>
#include <QtCore>
#include <ctime>
#include<QDesktopServices>
#include<QUrl>
#include<QMessageBox>
using namespace std;

DockerContainerScan::DockerContainerScan(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::DockerContainerScan)
{
    ui->setupUi(this);
    this->setWindowTitle("Docker Container Scanner");

    string info_usercmd = "sudo docker container ls -a";
    string info_rootcmd = "docker container ls -a";

    const char *info_cmdchr;

    // check user permission
    if (geteuid() != 0)
    {
        info_cmdchr = info_usercmd.c_str();
    }
    else
    {
        info_cmdchr = info_rootcmd.c_str();
    }

    // get the containers id information
    char information_buf[10240] = {0};
    FILE *information_pf = NULL;

    if( (information_pf = popen(info_cmdchr, "r")) == NULL )
    {
        cout << "Error" << endl;
    }
    string information_str;
    while(fgets(information_buf, sizeof information_buf, information_pf))
    {
        information_str += information_buf;
    }

    pclose(information_pf);

    unsigned int information_iSize =  information_str.size();
    if(information_iSize > 0 && information_str[information_iSize - 1] == '\n')  // linux
    {
        information_str = information_str.substr(0, information_iSize - 1);
    }

    // create QLabel
    QLabel* wordlabel = new QLabel(QString::fromStdString(information_str));
    // set height and width same as Scroll Widget
    wordlabel->resize(ui->scrollArea_c->width(),ui->scrollArea_c->height());
    // Insert QLabel into Scroll
    ui->scrollArea_c->setWidget(wordlabel);
}

void DockerContainerScan::on_pushButton_cscan_clicked()
{
    //id content
    QString qstr_id = ui->lineEdit_cid->text();
    string cstr_id = qstr_id.toStdString();

    // method content
    QString qstr_method = ui->comboBox_cmethod->currentText();
    string cstr_method = qstr_method.toStdString();

    // ssg content
    QString qstr_ssg = ui->comboBox_cssg->currentText();
    string cstr_ssg= qstr_ssg.toStdString();

    // profile content
    QString qstr_profile = ui->comboBox_cprofile->currentText();
    string cstr_profile= qstr_profile.toStdString();

    // time content
    time_t now = time(0);
    tm *ltm = localtime(&now);
    string time = to_string(ltm->tm_hour) + to_string(ltm->tm_min) + to_string(ltm->tm_sec);

    if (cstr_method == "CVE")
    {
        string report_name = cstr_id + "_" + time + "-cve-report.html";
        string cve_rootcmd = "oscap-docker container-cve " + cstr_id + " --results " + cstr_id + "_" + time + "-cve-results.xml" +
                " --report " + cstr_id + "_" + time + "-cve-report.html";
        string cve_usercmd = "sudo oscap-docker container-cve " + cstr_id + " --results " + cstr_id + "_" + time + "-cve-results.xml" +
                " --report " + cstr_id + "_" + time + "-cve-report.html";

        const char *cve_cmdchr;

        // check user permission
        if (geteuid() != 0)
        {
            cve_cmdchr = cve_usercmd.c_str();
        }
        else
        {
            cve_cmdchr = cve_rootcmd.c_str();
        }

        // enter the result file
        const char *report_namechr = report_name.c_str();
        chdir("/usr/share/xml/scap/result");

        // excute oval command & output result
        char result_buf[10240] = {0};
        FILE *result_pf = NULL;

        if( (result_pf = popen(cve_cmdchr, "r")) == NULL )
        {
            cout << "Error" << endl;
        }

        string str_result;
        while(fgets(result_buf, sizeof result_buf, result_pf))
        {
            str_result += result_buf;
        }

        pclose(result_pf);

        unsigned int result_iSize =  str_result.size();
        if(result_iSize > 0 && str_result[result_iSize  - 1] == '\n')  // linux
        {
            str_result = str_result.substr(0, result_iSize - 1);
        }

        // exception
        if(str_result == "")
        {
            QLabel* wordlabel = new QLabel(QString::fromStdString("Error, Please Check Whether the Container ID Is Correct OR This Container Is Not Based On RHEL."));
            wordlabel->resize(ui->scrollArea_cresult->width(),ui->scrollArea_cresult->height());
            ui->scrollArea_cresult->setWidget(wordlabel);
        }
        else
        {
            QLabel* wordlabel = new QLabel(QString::fromStdString(str_result));
            wordlabel->resize(ui->scrollArea_cresult->width(),ui->scrollArea_cresult->height());
            ui->scrollArea_cresult->setWidget(wordlabel);

            // open report html file
            QDesktopServices :: openUrl(QUrl(QLatin1String(report_namechr)));
        }

    }
    else if (cstr_method == "OVAL")
    {

        string report_name = cstr_id + "_" + time + "-oval-report.html";
        string ssg_name = " /usr/share/xml/scap/ssg/content/" + cstr_ssg + ".xml";
        string oval_rootcmd = "oscap-docker container " + cstr_id + " oval eval" + " --results " + cstr_id + "_" + time + "-oval-results.xml" +
                " --report " + report_name + ssg_name;
        string oval_usercmd = "sudo oscap-docker container " + cstr_id + " oval eval" + " --results " + cstr_id + "_" + time + "-oval-results.xml" +
                " --report " + report_name + ssg_name;

        const char *oval_cmdchr;

        // check user permission
        if (geteuid() != 0)
        {
            oval_cmdchr = oval_usercmd.c_str();
        }
        else
        {
            oval_cmdchr = oval_rootcmd.c_str();
        }

        // enter the result file
        const char *report_namechr = report_name.c_str();
        chdir("/usr/share/xml/scap/result");

        // excute oval command & output result
        char result_buf[10240] = {0};
        FILE *result_pf = NULL;

        if( (result_pf = popen(oval_cmdchr, "r")) == NULL )
        {
            cout << "Error" << endl;
        }

        string str_result;
        while(fgets(result_buf, sizeof result_buf, result_pf))
        {
            str_result += result_buf;
        }

        pclose(result_pf);

        unsigned int result_iSize =  str_result.size();
        if(result_iSize > 0 && str_result[result_iSize  - 1] == '\n')  // linux
        {
            str_result = str_result.substr(0, result_iSize - 1);
        }

        // exception
        if(str_result == "")
        {
            QLabel* wordlabel = new QLabel(QString::fromStdString("Error, Please Check whether the Container ID is Correct OR Select Other SSG/Profile."));
            wordlabel->resize(ui->scrollArea_cresult->width(),ui->scrollArea_cresult->height());
            ui->scrollArea_cresult->setWidget(wordlabel);
        }
        else
        {
            QLabel* wordlabel = new QLabel(QString::fromStdString(str_result));
            wordlabel->resize(ui->scrollArea_cresult->width(),ui->scrollArea_cresult->height());
            ui->scrollArea_cresult->setWidget(wordlabel);

            // open report html file
            QDesktopServices :: openUrl(QUrl(QLatin1String(report_namechr)));
        }
    }
    else if (cstr_method == "XCCDF")
    {
        string report_name = cstr_id + "_" + time + "-xccdf-report.html";
        string ssg_name = " /usr/share/xml/scap/ssg/content/" + cstr_ssg + ".xml";
        string profile_name = cstr_profile;
        string xccdf_rootcmd = "oscap-docker container " + cstr_id + " xccdf eval" + " --profile " + profile_name + " --results " + cstr_id + "_" + time + "-xccdf-results.xml" +
                " --report " + cstr_id + "_" + time + "-xccdf-report.html" +  ssg_name;
        string xccdf_usercmd = "sudo oscap-docker container " + cstr_id + " xccdf eval" + " --profile " + profile_name + " --results " + cstr_id + "_" + time + "-xccdf-results.xml" +
                " --report " + cstr_id + "_" + time + "-xccdf-report.html" +  ssg_name;

        const char *xccdf_cmdchr;

        // check user permission
        if (geteuid() != 0)
        {
            xccdf_cmdchr = xccdf_usercmd.c_str();
        }
        else
        {
            xccdf_cmdchr = xccdf_rootcmd.c_str();
        }

        // enter the result file
        const char *report_namechr = report_name.c_str();
        chdir("/usr/share/xml/scap/result");

        // excute oval command & output result
        char result_buf[10240] = {0};
        FILE *result_pf = NULL;

        if( (result_pf = popen(xccdf_cmdchr, "r")) == NULL )
        {
            cout << "Error" << endl;
        }

        string str_result;
        while(fgets(result_buf, sizeof result_buf, result_pf))
        {
            str_result += result_buf;
        }

        pclose(result_pf);

        unsigned int result_iSize =  str_result.size();
        if(result_iSize > 0 && str_result[result_iSize  - 1] == '\n')  // linux
        {
            str_result = str_result.substr(0, result_iSize - 1);
        }

        // exception
        if(str_result == "")
        {
            QLabel* wordlabel = new QLabel(QString::fromStdString("Error, Please Check whether the Container ID is Correct OR Select Other SSG/Profile."));
            wordlabel->resize(ui->scrollArea_cresult->width(),ui->scrollArea_cresult->height());
            ui->scrollArea_cresult->setWidget(wordlabel);
        }
        else
        {
            QLabel* wordlabel = new QLabel(QString::fromStdString(str_result));
            wordlabel->resize(ui->scrollArea_cresult->width(),ui->scrollArea_cresult->height());
            ui->scrollArea_cresult->setWidget(wordlabel);

            // open report html file
            QDesktopServices :: openUrl(QUrl(QLatin1String(report_namechr)));
        }
    }
}

DockerContainerScan::~DockerContainerScan()
{
    delete ui;
}

void DockerContainerScan::on_pushButton_cexit_clicked()
{
    this->close();
}

void DockerContainerScan::on_comboBox_cmethod_currentIndexChanged()
{
    switch (ui->comboBox_cmethod->currentIndex())
    {
        // case cve
        case 0:
            ui->comboBox_cssg->clear();
            ui->comboBox_cssg->insertItem(0, "NULL");
            ui->comboBox_cprofile->clear();
            ui->comboBox_cprofile->insertItem(0, "NULL");
            break;

        // case oval
        case 1:
            ui->comboBox_cssg->clear();
            ui->comboBox_cssg->insertItem(0, "ssg-firefox-oval");
            ui->comboBox_cssg->insertItem(1, "ssg-jre-oval");
            ui->comboBox_cssg->insertItem(2, "ssg-rhel6-oval");
            ui->comboBox_cssg->insertItem(3, "ssg-rhel7-oval");
            ui->comboBox_cprofile->clear();
            ui->comboBox_cprofile->insertItem(0, "NULL");
            break;

        //case xccdf
        case 2:
            ui->comboBox_cssg->clear();
            ui->comboBox_cssg->insertItem(0, "ssg-centos6-ds");
            ui->comboBox_cssg->insertItem(1, "ssg-centos6-xccdf");
            ui->comboBox_cssg->insertItem(2, "ssg-centos7-ds");
            ui->comboBox_cssg->insertItem(3, "ssg-centos7-xccdf");
            ui->comboBox_cssg->insertItem(4, "ssg-firefox-ds");
            ui->comboBox_cssg->insertItem(5, "ssg-firefox-xccdf");
            ui->comboBox_cssg->insertItem(6, "ssg-jre-ds");
            ui->comboBox_cssg->insertItem(7, "ssg-jre-xccdf");
            ui->comboBox_cssg->insertItem(8, "ssg-rhel6-ds");
            ui->comboBox_cssg->insertItem(9, "ssg-rhel6-xccdf");
            ui->comboBox_cssg->insertItem(10, "ssg-rhel7-ds");
            ui->comboBox_cssg->insertItem(11, "ssg-rhel7-xccdf");
            break;
    }
}

void DockerContainerScan::on_comboBox_cssg_currentIndexChanged()
{
    // method content
    QString qstr_ssg= ui->comboBox_cssg->currentText();
    string cstr_ssg = qstr_ssg.toStdString();

    switch (ui->comboBox_cssg->currentIndex())
    {
        // case ssg-centos6-ds
        case 0:
            if(cstr_ssg == "ssg-centos6-ds")
            {
                ui->comboBox_cprofile->clear();
                ui->comboBox_cprofile->insertItem(0,"CS2");
                ui->comboBox_cprofile->insertItem(1,"rht-ccp");
                ui->comboBox_cprofile->insertItem(2,"CSCF-RHEL6-MLS");
                ui->comboBox_cprofile->insertItem(3,"desktop");
                ui->comboBox_cprofile->insertItem(4,"nist-CL-IL-AL");
                ui->comboBox_cprofile->insertItem(5,"pci-dss");
                ui->comboBox_cprofile->insertItem(6,"C2S");
                ui->comboBox_cprofile->insertItem(7,"standard");
                ui->comboBox_cprofile->insertItem(8,"server");
                ui->comboBox_cprofile->insertItem(9,"fisma-medium-rhel6-server");
                ui->comboBox_cprofile->insertItem(10,"ftp-server");
                ui->comboBox_cprofile->insertItem(11,"stig-rhel6-disa");
                ui->comboBox_cprofile->insertItem(12,"usgcb-rhel6-server");
            }
            break;

        // case ssg-centos6-xccdf
        case 1:
            if(cstr_ssg == "ssg-centos6-xccdf")
            {
                ui->comboBox_cprofile->clear();
                ui->comboBox_cprofile->insertItem(0,"CS2");
                ui->comboBox_cprofile->insertItem(1,"rht-ccp");
                ui->comboBox_cprofile->insertItem(2,"CSCF-RHEL6-MLS");
                ui->comboBox_cprofile->insertItem(3,"desktop");
                ui->comboBox_cprofile->insertItem(4,"nist-CL-IL-AL");
                ui->comboBox_cprofile->insertItem(5,"pci-dss");
                ui->comboBox_cprofile->insertItem(6,"C2S");
                ui->comboBox_cprofile->insertItem(7,"standard");
                ui->comboBox_cprofile->insertItem(8,"server");
                ui->comboBox_cprofile->insertItem(9,"fisma-medium-rhel6-server");
                ui->comboBox_cprofile->insertItem(10,"ftp-server");
                ui->comboBox_cprofile->insertItem(11,"stig-rhel6-disa");
                ui->comboBox_cprofile->insertItem(12,"usgcb-rhel6-server");
           }
           break;

        // case ssg-centos7-ds
        case 2:
            if(cstr_ssg == "ssg-centos7-ds")
            {
                ui->comboBox_cprofile->clear();
                ui->comboBox_cprofile->insertItem(0,"stig-rhel7-disa");
                ui->comboBox_cprofile->insertItem(1,"rht-ccp");
                ui->comboBox_cprofile->insertItem(2,"cjis");
                ui->comboBox_cprofile->insertItem(3,"hipaa");
                ui->comboBox_cprofile->insertItem(4,"pci-dss");
                ui->comboBox_cprofile->insertItem(5,"C2S");
                ui->comboBox_cprofile->insertItem(6,"standard");
                ui->comboBox_cprofile->insertItem(7,"ospp42");
                ui->comboBox_cprofile->insertItem(8,"ospp");
                ui->comboBox_cprofile->insertItem(9,"nist-800-171-cui");
           }
           break;

        // case ssg-centos7-xccdf
        case 3:
            if(cstr_ssg == "ssg-centos7-xccdf")
            {
                ui->comboBox_cprofile->clear();
                ui->comboBox_cprofile->insertItem(0,"stig-rhel7-disa");
                ui->comboBox_cprofile->insertItem(1,"rht-ccp");
                ui->comboBox_cprofile->insertItem(2,"cjis");
                ui->comboBox_cprofile->insertItem(3,"hipaa");
                ui->comboBox_cprofile->insertItem(4,"pci-dss");
                ui->comboBox_cprofile->insertItem(5,"C2S");
                ui->comboBox_cprofile->insertItem(6,"standard");
                ui->comboBox_cprofile->insertItem(7,"ospp42");
                ui->comboBox_cprofile->insertItem(8,"ospp");
                ui->comboBox_cprofile->insertItem(9,"nist-800-171-cui");
           }
           break;

        // case ssg-firefox-ds
        case 4:
            if(cstr_ssg == "ssg-firefox-ds")
            {
                ui->comboBox_cprofile->clear();
                ui->comboBox_cprofile->insertItem(0,"stig-firefox-upstream");
            }
            break;

        // case ssg-firefox-xccdf
        case 5:
            if(cstr_ssg == "ssg-firefox-xccdf")
            {
                ui->comboBox_cprofile->clear();
                ui->comboBox_cprofile->insertItem(0,"stig-firefox-upstream");
            }
        break;

        // case ssg-jre-ds
        case 6:
            if(cstr_ssg == "ssg-jre-ds")
            {
                ui->comboBox_cprofile->clear();
                ui->comboBox_cprofile->insertItem(0,"stig-java-upstream");
            }
        break;

        // case ssg-firefox-xccdf
        case 7:
            if(cstr_ssg == "ssg-firefox-xccdf")
            {
                ui->comboBox_cprofile->clear();
                ui->comboBox_cprofile->insertItem(0,"stig-java-upstream");
            }
        break;

        // case ssg-rhel6-ds
        case 8:
            if(cstr_ssg == "ssg-rhel6-ds")
            {
                ui->comboBox_cprofile->clear();
                ui->comboBox_cprofile->insertItem(0,"CS2");
                ui->comboBox_cprofile->insertItem(1,"rht-ccp");
                ui->comboBox_cprofile->insertItem(2,"CSCF-RHEL6-MLS");
                ui->comboBox_cprofile->insertItem(3,"desktop");
                ui->comboBox_cprofile->insertItem(4,"nist-CL-IL-AL");
                ui->comboBox_cprofile->insertItem(5,"pci-dss");
                ui->comboBox_cprofile->insertItem(6,"C2S");
                ui->comboBox_cprofile->insertItem(7,"standard");
                ui->comboBox_cprofile->insertItem(8,"server");
                ui->comboBox_cprofile->insertItem(9,"fisma-medium-rhel6-server");
                ui->comboBox_cprofile->insertItem(10,"ftp-server");
                ui->comboBox_cprofile->insertItem(11,"stig-rhel6-disa");
                ui->comboBox_cprofile->insertItem(12,"usgcb-rhel6-server");
            }
            break;

        // case ssg-rhel6-xccdf
        case 9:
            if(cstr_ssg == "ssg-rhel6-xccdf")
            {
                ui->comboBox_cprofile->clear();
                ui->comboBox_cprofile->insertItem(0,"CS2");
                ui->comboBox_cprofile->insertItem(1,"rht-ccp");
                ui->comboBox_cprofile->insertItem(2,"CSCF-RHEL6-MLS");
                ui->comboBox_cprofile->insertItem(3,"desktop");
                ui->comboBox_cprofile->insertItem(4,"nist-CL-IL-AL");
                ui->comboBox_cprofile->insertItem(5,"pci-dss");
                ui->comboBox_cprofile->insertItem(6,"C2S");
                ui->comboBox_cprofile->insertItem(7,"standard");
                ui->comboBox_cprofile->insertItem(8,"server");
                ui->comboBox_cprofile->insertItem(9,"fisma-medium-rhel6-server");
                ui->comboBox_cprofile->insertItem(10,"ftp-server");
                ui->comboBox_cprofile->insertItem(11,"stig-rhel6-disa");
                ui->comboBox_cprofile->insertItem(12,"usgcb-rhel6-server");
            }
            break;

        // case ssg-rhel7-ds
        case 10:
            if(cstr_ssg == "ssg-rhel7-ds")
            {
                ui->comboBox_cprofile->clear();
                ui->comboBox_cprofile->insertItem(0,"stig-rhel7-disa");
                ui->comboBox_cprofile->insertItem(1,"rht-ccp");
                ui->comboBox_cprofile->insertItem(2,"cjis");
                ui->comboBox_cprofile->insertItem(3,"hipaa");
                ui->comboBox_cprofile->insertItem(4,"pci-dss");
                ui->comboBox_cprofile->insertItem(5,"C2S");
                ui->comboBox_cprofile->insertItem(6,"standard");
                ui->comboBox_cprofile->insertItem(7,"ospp42");
                ui->comboBox_cprofile->insertItem(8,"ospp");
                ui->comboBox_cprofile->insertItem(9,"nist-800-171-cui");
            }
            break;

        // case ssg-rhel7-xccdf
        case 11:
            if(cstr_ssg == "ssg-rhel7-xccdf")
            {
                ui->comboBox_cprofile->clear();
                ui->comboBox_cprofile->insertItem(0,"stig-rhel7-disa");
                ui->comboBox_cprofile->insertItem(1,"rht-ccp");
                ui->comboBox_cprofile->insertItem(2,"cjis");
                ui->comboBox_cprofile->insertItem(3,"hipaa");
                ui->comboBox_cprofile->insertItem(4,"pci-dss");
                ui->comboBox_cprofile->insertItem(5,"C2S");
                ui->comboBox_cprofile->insertItem(6,"standard");
                ui->comboBox_cprofile->insertItem(7,"ospp42");
                ui->comboBox_cprofile->insertItem(8,"ospp");
                ui->comboBox_cprofile->insertItem(9,"nist-800-171-cui");
            }
            break;
    }
}


