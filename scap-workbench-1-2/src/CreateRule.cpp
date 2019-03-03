#include "CreateRule.h"
#include <QMessageBox>
#include <QFileDialog>
#include <QProcess>

CreateRule::CreateRule(QWidget *parent) :
    QDialog(parent)
{
    mUI.setupUi(this);

    QObject::connect(
        mUI.OkButton, SIGNAL(clicked()),
        this, SLOT(on_Ok_clicked())
    );

    QObject::connect(
        mUI.CancelButton, SIGNAL(clicked()),
        this, SLOT(on_Cancel_clicked())
    );
}

CreateRule::~CreateRule()
{
//    delete ui;
}

void CreateRule::on_Ok_clicked(){
    if(mUI.rulename->text() == NULL || mUI.rulename->text() == ""){
        QMessageBox::information(NULL,tr("CreateRule"),tr("Pleass enter rule file name!"));
        return;
    }
    if(mUI.groupid->text() == NULL || mUI.groupid->text() == ""){
        QMessageBox::information(NULL,tr("CreateRule"),tr("Pleass enter group id!"));
        return;
    }
    if(mUI.grouptitle->text() == NULL || mUI.grouptitle->text() == ""){
        QMessageBox::information(NULL,tr("CreateRule"),tr("Pleass enter group title!"));
        return;
    }
    if(mUI.groupdescription->text() == NULL || mUI.groupdescription->text() == ""){
        QMessageBox::information(NULL,tr("CreateRule"),tr("Pleass enter group description!"));
        return;
    }
    if(mUI.ruleid->text() == NULL || mUI.ruleid->text() == ""){
        QMessageBox::information(NULL,tr("CreateRule"),tr("Pleass enter rule id!"));
        return;
    }
    if(mUI.ruleserverity->text() == NULL || mUI.ruleserverity->text() == ""){
        QMessageBox::information(NULL,tr("CreateRule"),tr("Pleass enter rule serverity!"));
        return;
    }
    if(mUI.ruletitle->text() == NULL || mUI.ruletitle->text() == ""){
        QMessageBox::information(NULL,tr("CreateRule"),tr("Pleass enter rule title!"));
        return;
    }
    if(mUI.ruledescription->text() == NULL || mUI.ruledescription->text() == ""){
        QMessageBox::information(NULL,tr("CreateRule"),tr("Pleass enter ruled ruledescription!"));
        return;
    }
    if(mUI.ovalid->text() == NULL || mUI.ovalid->text() == ""){
        QMessageBox::information(NULL,tr("CreateRule"),tr("Pleass enter oval id!"));
        return;
    }

    QString rulename = mUI.rulename->text();
    QString groupid = mUI.groupid->text();
    QString grouptitle = mUI.grouptitle->text();
    QString groupdescription = mUI.groupdescription->text();
    QString ruleid = mUI.ruleid->text();
    QString ruleseverity = mUI.ruleserverity->text();
    QString ruletitle = mUI.ruletitle->text();
    QString ruledescription = mUI.ruledescription->text();
    QString ovalid = mUI.ovalid->text();;
    /**
     * craterule and updata shared_guide.xslt.
     */

    const QString path = "/root/scap-security-guide/shared/xccdf/ncsist/"+rulename+".xml";
    QFile file(path);
    file.open(QIODevice::WriteOnly);
    QString datastr = "<Group id=\""+groupid+"\">\n"+
                      "<title>"+grouptitle+"</title>\n"+
                      "<description>"+groupdescription+"</description>\n\n"+
                      "<Rule id=\""+ruleid+"\" severity=\""+ruleseverity+"\" prodtype=\"rhel7\">\n"+
                      "<title>"+ruletitle+"</title>\n"+
                      "<description>"+ruledescription+"</description>\n\n"+
                      "<ocil>TBD.</ocil>\n"+
                      "<rationale>TBD.</rationale>\n"+
                      "<ident prodtype=\"rhel7\" cce=\"TBD\" />\n"+
                      "<oval id=\""+ovalid+"\" />\n"+
                      "<ref nist=\"TBD\" disa=\"TBD\" srg=\"TBD\" />\n"+
                      "</Rule>\n\n"+
                      "</Group>";

    const char* data = datastr.toLatin1().data();
    file.write(data);
    file.close();

    const QString path2 = "/root/scap-security-guide/shared/xccdf/shared_guide.xslt";
    const QString path3 = "/root/scap-security-guide/shared/xccdf/shared_guide1.xslt";
    QFile file3(path3);
    file3.open(QIODevice::WriteOnly);
    QFile file2(path2);
    file2.open(QIODevice::ReadWrite);
    datastr = "";
    QString temp = "";
    QString cmp = "  <xsl:template match=\"Group[@id='ncsist']\">\n";
    while(!file2.atEnd()) {
        temp = file2.readLine();
        file3.write(temp.toLatin1().data());
        if(!cmp.compare(temp)){
              break;
        }
    }
    cmp = "      <xsl:copy-of select=\"@*|node()\" />\n";
    while(!file2.atEnd()) {
        temp = file2.readLine();
        file3.write(temp.toLatin1().data());
        if(!cmp.compare(temp)){
              QString tp = "      <xsl:apply-templates select=\"document(concat($SHARED_RP, \'/xccdf/ncsist/"+rulename+".xml\'))\" />\n";
              const char* data2 = tp.toLatin1().data();
              file3.write(data2);
        }
    }
    file2.close();
    file3.close();
    QProcess::execute("/root/scap-security-guide/shared/xccdf/changeguide.sh");
    QMessageBox::information(NULL,tr("CreateRule"),tr("Create Success!"));
    this->close();
}

void CreateRule::on_Cancel_clicked(){
    this->close();
}

CreateRule* globalCreateRule = NULL;
