#include "CreateOval.h"
#include <QMessageBox>
#include <QFileDialog>
#include <QProcess>
#include <QTextStream>

CreateOval::CreateOval(QWidget *parent) :
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

CreateOval::~CreateOval()
{
//    delete ui;
}


void CreateOval::on_Ok_clicked(){
    if(mUI.ovalname->text() == NULL || mUI.ovalname->text() == ""){
        QMessageBox::information(NULL,tr("CreateOVAL"),tr("Pleass enter oval file name!"));
        return;
    }
    if(mUI.ovalid->text() == NULL || mUI.ovalid->text() == ""){
        QMessageBox::information(NULL,tr("CreateOVAL"),tr("Pleass enter oval id!"));
        return;
    }
    if(mUI.ovaltitle->text() == NULL || mUI.ovaltitle->text() == ""){
        QMessageBox::information(NULL,tr("CreateOVAL"),tr("Pleass enter oval title!"));
        return;
    }
    if(mUI.ovaldescription->text() == NULL || mUI.ovaldescription->text() == ""){
        QMessageBox::information(NULL,tr("CreateOVAL"),tr("Pleass enter oval description!"));
        return;
    }
    if(mUI.ovalcomment->text() == NULL || mUI.ovalcomment->text() == ""){
        QMessageBox::information(NULL,tr("CreateOVAL"),tr("Pleass enter oval comment!"));
        return;
    }
    if(mUI.ovalfilepath->text() == NULL || mUI.ovalfilepath->text() == ""){
        QMessageBox::information(NULL,tr("CreateOVAL"),tr("Pleass enter filepath!"));
        return;
    }
//    if(mUI.ovalfilename->text() == NULL || mUI.ovalfilename->text() == ""){
//        QMessageBox::information(NULL,tr("CreateOVAL"),tr("Pleass enter filename!"));
//        return;
//    }
    QString ovalname = mUI.ovalname->text();
    QString ovalid = mUI.ovalid->text();
    QString ovaltitle = mUI.ovaltitle->text();
    QString ovaldescription = mUI.ovaldescription->text();
    QString ovalcomment = mUI.ovalcomment->text();
    QString ovalfilepath = mUI.ovalfilepath->text();
    // QString ovalfilename = mUI.ovalfilename->text();

    /**
     * cratepOval.
     */

    const QString path = "/root/scap-security-guide/rhel7/checks/oval/"+ovalname+".xml";
    QFile file(path);
    file.open(QIODevice::WriteOnly | QIODevice::Text);


    QTextStream out(&file);
    QString datastr = QString("<def-group>\n");
    const char* data = datastr.toLatin1().data();
    file.write(data);
    datastr = QString("    <definition class=\"compliance\" id=\"") + ovalid + QString("\" version=\"1\">\n");
    data = datastr.toLatin1().data();
    file.write(data);
    datastr = QString("        <metadata>\n");
    data = datastr.toLatin1().data();
    file.write(data);
    datastr = QString("            <title>") + ovaltitle + QString("</title>\n");
    data = datastr.toLatin1().data();
    file.write(data);
    datastr = QString("            <affected family=\"unix\">\n");
    data = datastr.toLatin1().data();
    file.write(data);
    datastr = QString("                <platform>Red Hat Enterprise Linux 7</platform>\n");
    data = datastr.toLatin1().data();
    file.write(data);
    datastr = QString("            </affected>\n");
    data = datastr.toLatin1().data();
    file.write(data);
    datastr = QString("            <description>") + ovaldescription + QString("</description>\n");
    data = datastr.toLatin1().data();
    file.write(data);
    datastr = QString("        </metadata>\n");
    data = datastr.toLatin1().data();
    file.write(data);
    datastr = QString("        <criteria>\n");
    data = datastr.toLatin1().data();
    file.write(data);
    datastr = QString("            <criterion comment=\"") + ovalcomment + QString("\" test_ref=\"test_") + ovalid + QString("\" />\n");
    data = datastr.toLatin1().data();
    file.write(data);
    datastr = QString("        </criteria>\n");
    data = datastr.toLatin1().data();
    file.write(data);
    datastr = QString("    </definition>\n\n");
    data = datastr.toLatin1().data();
    file.write(data);
    datastr = QString("    <ind:textfilecontent54_test check=\"all\"\n");
    data = datastr.toLatin1().data();
    file.write(data);
    datastr = QString("    check_existence=\"all_exist\"\n");
    data = datastr.toLatin1().data();
    file.write(data);
    datastr = QString("    comment=\"check ") + ovalcomment + QString(" file if is exist\"\n");
    data = datastr.toLatin1().data();
    file.write(data);
    datastr = QString("    id=\"test_") + ovalid + QString("\" version=\"1\">\n");
    data = datastr.toLatin1().data();
    file.write(data);
    datastr = QString("        <ind:object object_ref=\"obj_") + ovalid + QString("\" />\n");
    data = datastr.toLatin1().data();
    file.write(data);
    // datastr = QString("        <unix:state state_ref=\"state_") + ovalid + QString("\" />\n");
    // data = datastr.toLatin1().data();
    // file.write(data);
    datastr = QString("    </ind:textfilecontent54_test>\n\n");
    data = datastr.toLatin1().data();
    file.write(data);
    datastr = QString("    <ind:textfilecontent54_object id=\"obj_") + ovalid + QString("\" version=\"1\">\n");
    data = datastr.toLatin1().data();
    file.write(data);
    datastr = QString("        <ind:filepath>") + ovalfilepath + QString("</ind:filepath>\n");
    data = datastr.toLatin1().data();
    file.write(data);
    datastr = QString("        <ind:pattern operation=\"pattern match\">0</ind:pattern>\n");
    data = datastr.toLatin1().data();
    file.write(data);
    datastr = QString("        <ind:instance datatype=\"int\" operation=\"equals\">1</ind:instance>\n");
    data = datastr.toLatin1().data();
    file.write(data);


    datastr = QString("    </ind:textfilecontent54_object>\n\n");
    data = datastr.toLatin1().data();
    file.write(data);
    // datastr = QString("    <unix:file_state id=\"state_") + ovalid + QString("\" version=\"1\">\n");
    // data = datastr.toLatin1().data();
    // file.write(data);
    // datastr = QString("        <unix:filename>") + ovalfilename + QString("</unix:filename>\n");
    // data = datastr.toLatin1().data();
    // file.write(data);
    // datastr = QString("    </unix:file_state>\n");
    // data = datastr.toLatin1().data();
    // file.write(data);
    datastr = QString("</def-group>\n");
    data = datastr.toLatin1().data();
    file.write(data);

    file.close();

    QMessageBox::information(NULL,tr("CreateOVAL"),tr("Create Success!"));
    this->close();
}

void CreateOval::on_Cancel_clicked(){
    this->close();
}

CreateOval* globalCreateOval = NULL;
