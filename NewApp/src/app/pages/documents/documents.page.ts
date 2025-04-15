import { Component, OnInit } from '@angular/core';
import { AuthService } from '../../services/auth.service';
import { DocumentsService } from '../../services/documents.service';
import { AlertController } from '@ionic/angular';
import { saveAs } from 'file-saver';
import { IonicModule } from '@ionic/angular';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-documents',
  templateUrl: './documents.page.html',
  styleUrls: ['./documents.page.scss'],
  standalone: false,
})
export class DocumentsPage implements OnInit {
  user: any;
  documents: any[] = [];
  selectedFile: File | null = null;
  titre: string = '';
  selectedMedecinId: string = '';
  medecins: any[] = [];

  constructor(
    private authService: AuthService,
    private documentsService: DocumentsService,
    private alertCtrl: AlertController
  ) {}

  ngOnInit() {
    this.user = this.authService.getUser();
    this.loadDocuments();
    this.loadMedecins();
  }

  loadDocuments() {
    const request = this.user.role === 'patient'
      ? this.documentsService.getPatientDocuments()
      : this.documentsService.getMedecinDocuments();

    request.subscribe({
      next: (data) => (this.documents = data),
      error: (err) => console.error('Erreur chargement documents:', err),
    });
  }

  loadMedecins() {
    if (this.user.role === 'patient') {
      this.documentsService.getPatientMedecins().subscribe({
        next: (data) => {
          this.medecins = data;
          console.log('Médecins avec rendez-vous:', data);
        },
        error: (err) => console.error('Erreur chargement médecins:', err),
      });
    }
  }

  onFileSelected(event: any) {
    this.selectedFile = event.target.files[0];
  }

  async uploadDocument() {
    if (!this.selectedFile || !this.titre || !this.selectedMedecinId) {
      const alert = await this.alertCtrl.create({
        header: 'Erreur',
        message: 'Veuillez remplir tous les champs.',
        buttons: ['OK'],
      });
      await alert.present();
      return;
    }

    const formData = new FormData();
    formData.append('patient_id', this.user.id);
    formData.append('medecin_id', this.selectedMedecinId);
    formData.append('titre', this.titre);
    formData.append('fichier', this.selectedFile);

    this.documentsService.uploadDocument(formData).subscribe({
      next: async () => {
        this.loadDocuments();
        this.titre = '';
        this.selectedFile = null;
        this.selectedMedecinId = '';
        const alert = await this.alertCtrl.create({
          header: 'Succès',
          message: 'Document envoyé avec succès.',
          buttons: ['OK'],
        });
        await alert.present();
      },
      error: async (err) => {
        console.error('Erreur envoi document:', err);
        const alert = await this.alertCtrl.create({
          header: 'Erreur',
          message: 'Erreur lors de l’envoi du document.',
          buttons: ['OK'],
        });
        await alert.present();
      },
    });
  }

  downloadDocument(docId: number) {
    this.documentsService.downloadDocument(docId).subscribe({
      next: (blob) => {
        const doc = this.documents.find(d => d.id === docId);
        saveAs(blob, doc.titre);
      },
      error: (err) => console.error('Erreur téléchargement document:', err),
    });
  }

  async annotateDocument(doc: any) {
    const alert = await this.alertCtrl.create({
      header: 'Ajouter une remarque',
      inputs: [{ name: 'remarques', type: 'text', placeholder: 'Remarques' }],
      buttons: [
        { text: 'Annuler', role: 'cancel' },
        {
          text: 'Valider',
          handler: (data) => {
            this.documentsService.annotateDocument(doc.id, data.remarques).subscribe({
              next: () => this.loadDocuments(),
              error: (err) => console.error('Erreur annotation document:', err),
            });
          },
        },
      ],
    });
    await alert.present();
  }
}