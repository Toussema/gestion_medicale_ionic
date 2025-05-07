import { Component, OnInit } from '@angular/core';
import { AuthService } from '../../services/auth.service';
import { DocumentsService } from '../../services/documents.service';
import { AlertController } from '@ionic/angular';
import { saveAs } from 'file-saver';
import { DomSanitizer, SafeResourceUrl } from '@angular/platform-browser';

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
  previewUrl: SafeResourceUrl | null = null;
  previewType: 'pdf' | 'image' | null = null;
  isLoadingPreview: boolean = false;

  constructor(
    private authService: AuthService,
    private documentsService: DocumentsService,
    private alertCtrl: AlertController,
    private sanitizer: DomSanitizer
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
      next: (data) => {
        this.documents = data;
        console.log('Documents chargés:', data);
      },
      error: async (err) => {
        console.error('Erreur chargement documents:', err);
        await this.showAlert('Erreur', 'Impossible de charger les documents.');
      },
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
      await this.showAlert('Erreur', 'Veuillez remplir tous les champs.');
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
        await this.showAlert('Succès', 'Document envoyé avec succès.');
      },
      error: async (err) => {
        console.error('Erreur envoi document:', err);
        await this.showAlert('Erreur', 'Erreur lors de l’envoi du document.');
      },
    });
  }

  downloadDocument(docId: number) {
    this.documentsService.downloadDocument(docId).subscribe({
      next: (blob) => {
        const doc = this.documents.find(d => d.id === docId);
        saveAs(blob, doc.titre);
      },
      error: async (err) => {
        console.error('Erreur téléchargement document:', err);
        await this.showAlert('Erreur', 'Impossible de télécharger le document.');
      },
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
              error: async (err) => {
                console.error('Erreur annotation document:', err);
                await this.showAlert('Erreur', 'Impossible d’annoter le document.');
              },
            });
          },
        },
      ],
    });
    await alert.present();
  }

  previewDocument(docId: number) {
    console.log('Tentative de prévisualisation du document ID:', docId);
    this.isLoadingPreview = true;
    this.documentsService.downloadDocument(docId, true).subscribe({
      next: (blob) => {
        console.log('Blob reçu:', blob);
        const url = window.URL.createObjectURL(blob);
        if (blob.type === 'application/pdf') {
          this.previewType = 'pdf';
          this.previewUrl = this.sanitizer.bypassSecurityTrustResourceUrl(url);
        } else if (blob.type.startsWith('image/')) {
          this.previewType = 'image';
          this.previewUrl = this.sanitizer.bypassSecurityTrustResourceUrl(url);
        } else {
          this.isLoadingPreview = false;
          this.showAlert('Erreur', 'Type de fichier non supporté pour la prévisualisation.');
          window.URL.revokeObjectURL(url);
          return;
        }
        this.isLoadingPreview = false;
        console.log('Preview URL généré:', url);
      },
      error: async (err) => {
        console.error('Erreur prévisualisation document:', err);
        this.isLoadingPreview = false;
        await this.showAlert('Erreur', err.status === 403 ? 'Accès refusé' : 'Impossible de prévisualiser le document.');
      },
    });
  }

  closePreview() {
    if (this.previewUrl) {
      const url = (this.previewUrl as any).changingThisBreaksApplicationSecurity;
      window.URL.revokeObjectURL(url);
    }
    this.previewUrl = null;
    this.previewType = null;
  }

  async showAlert(header: string, message: string) {
    const alert = await this.alertCtrl.create({
      header,
      message,
      buttons: ['OK'],
    });
    await alert.present();
  }
}