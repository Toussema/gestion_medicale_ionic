import { Component } from '@angular/core';
import { RendezVousService } from 'src/app/services/rendez-vous.service';
import { AuthService } from 'src/app/services/auth.service';

@Component({
    selector: 'app-rendez-vous',
    templateUrl: './rendez-vous.page.html',
    styleUrls: ['./rendez-vous.page.scss'],
    standalone: false
})
export class RendezVousPage {
    rendezVous: any[] = [];
    userRole: string = '';

    constructor(private rdvService: RendezVousService, private authService: AuthService) {}

    ionViewWillEnter() {
        const user = this.authService.getUser();
        this.userRole = user ? user.role : '';
        this.loadRendezVous();
    }

    loadRendezVous() {
        this.rdvService.getRendezVous().subscribe({
            next: (data) => this.rendezVous = data,
            error: (err) => console.error('Erreur:', err)
        });
    }

    annulerRdv(rdvId: string) {
        this.rdvService.annulerRendezVous(rdvId).subscribe({
            next: () => this.loadRendezVous(),
            error: (err) => alert('Erreur: ' + err.error.message)
        });
    }
}