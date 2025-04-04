import { Component, OnInit } from '@angular/core';
import { AuthService } from '../../services/auth.service';
import { DocumentsService } from '../../services/documents.service';
import { AlertController } from '@ionic/angular';
import { saveAs } from 'file-saver';

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
  selectedMedecinId: string = ''; // Remplace medecinId
  medecins: any[] = []; // Liste des médecins

  constructor(
    private authService: AuthService,
    private documentsService: DocumentsService,
    private alertCtrl: AlertController
  ) {}

  ngOnInit() {
    this.user = this.authService.getUser();
    this.loadDocuments();
    this.loadMedecins(); // Charger les médecins
  }

  loadDocuments() {
    const request = this.user.role === 'patient'
      ? this.documentsService.getPatientDocuments()
      : this.documentsService.getMedecinDocuments();

    request.subscribe({
      next: (data) => (this.documents = data),
      error: (err) => console.error(err),
    });
  }

  loadMedecins() {
    this.documentsService.getMedecins().subscribe({
      next: (data) => {
        this.medecins = data;
      },
      error: (err) => console.error(err),
    });
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
    formData.append('medecin_id', this.selectedMedecinId); // Utiliser l’ID sélectionné
    formData.append('titre', this.titre);
    formData.append('fichier', this.selectedFile);

    this.documentsService.uploadDocument(formData).subscribe({
      next: () => {
        this.loadDocuments();
        this.titre = '';
        this.selectedFile = null;
        this.selectedMedecinId = '';
      },
      error: (err) => console.error(err),
    });
  }

  downloadDocument(docId: number) {
    this.documentsService.downloadDocument(docId).subscribe({
      next: (blob) => {
        const doc = this.documents.find(d => d.id === docId);
        saveAs(blob, doc.titre);
      },
      error: (err) => console.error(err),
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
              error: (err) => console.error(err),
            });
          },
        },
      ],
    });
    await alert.present();
  }
}