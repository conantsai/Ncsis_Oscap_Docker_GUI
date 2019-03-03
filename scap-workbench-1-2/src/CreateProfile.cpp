#include "CreateProfile.h"
#include <QMessageBox>
#include <QFileDialog>
#include <QProcess>

CreateProfile::CreateProfile(QWidget *parent) :
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

CreateProfile::~CreateProfile()
{
    //delete ui;
}

void CreateProfile::on_Ok_clicked(){
    if(mUI.profilename->text() == NULL || mUI.profilename->text() == ""){
        QMessageBox::information(NULL,tr("CreateProfile"),tr("Pleass enter profile file name!"));
        return;
    }
    if(mUI.profileid->text() == NULL || mUI.profileid->text() == ""){
        QMessageBox::information(NULL,tr("CreateProfile"),tr("Pleass enter profile id!"));
        return;
    }
    if(mUI.profiletitle->text() == NULL || mUI.profiletitle->text() == ""){
        QMessageBox::information(NULL,tr("CreateProfile"),tr("Pleass enter profile title!"));
        return;
    }
    if(mUI.profiledescription->text() == NULL || mUI.profiledescription->text() == ""){
        QMessageBox::information(NULL,tr("CreateProfile"),tr("Pleass enter profile description!"));
        return;
    }
    if(mUI.selectidref->text() == NULL || mUI.selectidref->text() == ""){
        QMessageBox::information(NULL,tr("CreateProfile"),tr("Pleass enter select idref!"));
        return;
    }
    if(mUI.selected->text() == NULL || mUI.selected->text() == ""){
        QMessageBox::information(NULL,tr("CreateProfile"),tr("Pleass enter selected!"));
        return;
    }
    if(mUI.selected->text() != "true" && mUI.selected->text() != "false"){
        QMessageBox::information(NULL,tr("CreateProfile"),tr("Pleass enter true or false to selected!"));
        return;
    }
    QString profilename = mUI.profilename->text();
    QString profileid = mUI.profileid->text();
    QString profiletitle = mUI.profiletitle->text();
    QString profiledescription = mUI.profiledescription->text();
    QString selectidref = mUI.selectidref->text();
    QString selected = mUI.selected->text();

    /**
     * crateprofile and updata guide.xslt.
     */

    const QString path = "/root/scap-security-guide/rhel7/profiles/"+profilename+".xml";
    QFile file(path);
    file.open(QIODevice::ReadWrite);
    QString datastr = "<Profile id=\"" + profileid+ "\">\n"+
        "<title>"+profiletitle+"</title>\n"+
        "<description>"+profiledescription+"</description>\n\n"+
        "<select idref=\""+selectidref+"\" selected=\""+selected+"\" />\n\n"+
        "</Profile>";
    const char* data = datastr.toLatin1().data();
    file.write(data);
    file.close();
    const QString path2 = "/root/scap-security-guide/rhel7/guide.xslt";
    const QString path3 = "/root/scap-security-guide/rhel7/guide1.xslt";
    QFile file3(path3);
    file3.open(QIODevice::WriteOnly);
    QFile file2(path2);
    file2.open(QIODevice::ReadWrite);
    datastr = "";
    QString temp = "";
    QString cmp = "      <!-- Adding profiles here -->\n";
    while(!file2.atEnd()) {
        temp = file2.readLine();
        file3.write(temp.toLatin1().data());
        if(!cmp.compare(temp)){
              QString tp = "      <xsl:apply-templates select=\"document(\'profiles/"+profilename+".xml\')\" />\n";
              const char* data2 = tp.toLatin1().data();
              file3.write(data2);
        }
    }

    file2.close();
    file3.close();
    QProcess::execute("/root/scap-security-guide/rhel7/changeguide.sh");

    QMessageBox::information(NULL,tr("CreateProfile"),tr("Create Success!"));
    this->close();
}

void CreateProfile::on_Cancel_clicked(){
    this->close();
}

CreateProfile* globalCreateProfile = NULL;
